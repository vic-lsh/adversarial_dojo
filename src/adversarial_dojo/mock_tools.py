from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from adversarial_dojo.models import MockEnvironment, MockMcpServer, ToolCallRecord


class ToolInvocationRecorder:
    def __init__(self, log_path: str | Path | None = None) -> None:
        self.log_path = Path(log_path) if log_path is not None else None
        self.calls: list[ToolCallRecord] = []
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, call: ToolCallRecord) -> None:
        self.calls.append(call)
        if self.log_path is None:
            return
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(call.model_dump_json() + "\n")


class MockToolExecutor:
    def __init__(
        self,
        environment: MockEnvironment,
        recorder: ToolInvocationRecorder | None = None,
        state_path: str | Path | None = None,
    ) -> None:
        self.environment = environment
        self.recorder = recorder or ToolInvocationRecorder()
        self.state_path = Path(state_path) if state_path is not None else None
        self._call_counts: dict[str, int] = {}
        if self.state_path is not None:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.state_path.exists():
                self._write_state(_empty_state())

    def invoke(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        server_name: str | None = None,
    ) -> ToolCallRecord:
        arguments = arguments or {}
        server, tool = self.environment.find_tool(server_name, tool_name)
        key = f"{server.name}.{tool.name}"
        call_index = self._call_counts.get(key, 0)
        self._call_counts[key] = call_index + 1
        response = tool.select_response(arguments, call_index=call_index)
        state = self._read_state()
        dynamic = _dynamic_tool_result(server.name, tool.name, arguments, state)
        if dynamic is None and _is_stateful_write(server.name, tool.name):
            dynamic = _apply_stateful_write(server.name, tool.name, arguments, state)
            self._write_state(state)
        call = ToolCallRecord(
            server_name=server.name,
            tool_name=tool.name,
            arguments=arguments,
            result_content=dynamic["content"] if dynamic is not None else response.content,
            structured_content=dynamic["structured_content"] if dynamic is not None else response.structured_content,
            is_error=dynamic["is_error"] if dynamic is not None else response.is_error,
        )
        self.recorder.record(call)
        return call

    def _read_state(self) -> dict[str, Any]:
        if self.state_path is None or not self.state_path.exists():
            return _empty_state()
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _write_state(self, state: dict[str, Any]) -> None:
        if self.state_path is None:
            return
        self.state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def load_jsonl_calls(path: str | Path) -> list[ToolCallRecord]:
    call_path = Path(path)
    if not call_path.exists():
        return []
    calls: list[ToolCallRecord] = []
    with call_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                calls.append(ToolCallRecord.model_validate(json.loads(line)))
    return calls


def server_to_environment(server: MockMcpServer) -> MockEnvironment:
    return MockEnvironment(mcp_servers=[server])


def _empty_state() -> dict[str, Any]:
    return {
        "docs": {},
        "gmail_drafts": [],
        "gmail_sent": [],
        "chat_messages": {},
        "sheets": {},
    }


def _is_stateful_write(server_name: str, tool_name: str) -> bool:
    return (server_name, tool_name) in {
        ("docs", "create_doc"),
        ("docs", "modify_doc_text"),
        ("gmail", "draft_gmail_message"),
        ("gmail", "send_gmail_message"),
        ("chat", "send_message"),
        ("sheets", "create_spreadsheet"),
        ("sheets", "modify_sheet_values"),
    }


def _dynamic_tool_result(
    server_name: str,
    tool_name: str,
    arguments: dict[str, Any],
    state: dict[str, Any],
) -> dict[str, Any] | None:
    if server_name == "docs" and tool_name == "search_docs":
        query = str(arguments.get("query", "")).lower()
        matches = [
            {"id": doc_id, "name": doc["name"]}
            for doc_id, doc in state["docs"].items()
            if not query or query in doc["name"].lower()
        ]
        if matches:
            return {"content": json.dumps({"documents": matches}), "structured_content": {"documents": matches}, "is_error": False}
    if server_name == "docs" and tool_name in {"get_doc_content", "get_doc_as_markdown"}:
        doc_id = str(arguments.get("doc_id", ""))
        doc = state["docs"].get(doc_id)
        if doc is not None:
            return {"content": doc["content"], "structured_content": {"doc_id": doc_id, "name": doc["name"]}, "is_error": False}
    if server_name == "chat" and tool_name == "get_messages":
        space = str(arguments.get("space", arguments.get("space_id", "")))
        messages = state["chat_messages"].get(space, [])
        if messages:
            return {"content": json.dumps({"messages": messages}), "structured_content": {"messages": messages}, "is_error": False}
    if server_name == "gmail" and tool_name == "search_gmail_messages":
        query = str(arguments.get("query", "")).lower()
        messages = [
            msg for msg in (state["gmail_drafts"] + state["gmail_sent"])
            if not query or query in json.dumps(msg).lower()
        ]
        if messages:
            payload = [{"id": msg["id"], "subject": msg["subject"], "to": msg.get("to", ""), "body": msg["body"]} for msg in messages]
            return {"content": json.dumps({"messages": payload}), "structured_content": {"messages": payload}, "is_error": False}
    if server_name == "sheets" and tool_name == "read_sheet_values":
        sheet_id = str(arguments.get("spreadsheet_id", arguments.get("sheet_id", "")))
        sheet = state["sheets"].get(sheet_id)
        if sheet is not None:
            return {"content": sheet["content"], "structured_content": {"spreadsheet_id": sheet_id, "title": sheet["title"]}, "is_error": False}
    if server_name == "drive" and tool_name == "search_drive_files":
        query = str(arguments.get("query", "")).lower()
        docs = [
            {"id": doc_id, "name": doc["name"], "mimeType": "application/vnd.google-apps.document"}
            for doc_id, doc in state["docs"].items()
            if not query or query in doc["name"].lower()
        ]
        sheets = [
            {"id": sheet_id, "name": sheet["title"], "mimeType": "application/vnd.google-apps.spreadsheet"}
            for sheet_id, sheet in state["sheets"].items()
            if not query or query in sheet["title"].lower()
        ]
        files = docs + sheets
        if files:
            return {"content": json.dumps({"files": files}), "structured_content": {"files": files}, "is_error": False}
    return None


def _apply_stateful_write(
    server_name: str,
    tool_name: str,
    arguments: dict[str, Any],
    state: dict[str, Any],
) -> dict[str, Any]:
    if server_name == "docs" and tool_name == "create_doc":
        doc_id = f"doc_{secrets.token_hex(4)}"
        name = str(arguments.get("title", "Untitled Document"))
        state["docs"][doc_id] = {"name": name, "content": ""}
        return {"content": f"Created document {name} ({doc_id})", "structured_content": {"doc_id": doc_id, "name": name}, "is_error": False}
    if server_name == "docs" and tool_name == "modify_doc_text":
        doc_id = str(arguments.get("doc_id", ""))
        content = str(arguments.get("text", arguments.get("content", "")))
        doc = state["docs"].setdefault(doc_id or f"doc_{secrets.token_hex(4)}", {"name": "Untitled Document", "content": ""})
        doc["content"] += content
        return {"content": "document updated", "structured_content": {"doc_id": doc_id or None}, "is_error": False}
    if server_name == "gmail" and tool_name in {"draft_gmail_message", "send_gmail_message"}:
        msg_id = f"gmail_{secrets.token_hex(4)}"
        message = {
            "id": msg_id,
            "subject": str(arguments.get("subject", "")),
            "body": str(arguments.get("body", "")),
            "to": str(arguments.get("to", "")),
            "cc": str(arguments.get("cc", "")),
            "bcc": str(arguments.get("bcc", "")),
        }
        bucket = "gmail_drafts" if tool_name == "draft_gmail_message" else "gmail_sent"
        state[bucket].append(message)
        return {"content": "draft saved" if bucket == "gmail_drafts" else "message sent", "structured_content": {"message_id": msg_id}, "is_error": False}
    if server_name == "chat" and tool_name == "send_message":
        space = str(arguments.get("space", arguments.get("space_id", "default")))
        message = {"text": str(arguments.get("text", arguments.get("message", "")))}
        state["chat_messages"].setdefault(space, []).append(message)
        return {"content": "message sent", "structured_content": {"space": space}, "is_error": False}
    if server_name == "sheets" and tool_name == "create_spreadsheet":
        sheet_id = f"sheet_{secrets.token_hex(4)}"
        title = str(arguments.get("title", "Untitled Spreadsheet"))
        state["sheets"][sheet_id] = {"title": title, "content": ""}
        return {"content": f"Created spreadsheet {title} ({sheet_id})", "structured_content": {"spreadsheet_id": sheet_id, "title": title}, "is_error": False}
    if server_name == "sheets" and tool_name == "modify_sheet_values":
        sheet_id = str(arguments.get("spreadsheet_id", arguments.get("sheet_id", "")))
        values = arguments.get("values", arguments.get("data", ""))
        sheet = state["sheets"].setdefault(sheet_id or f"sheet_{secrets.token_hex(4)}", {"title": "Untitled Spreadsheet", "content": ""})
        sheet["content"] = json.dumps(values)
        return {"content": "sheet updated", "structured_content": {"spreadsheet_id": sheet_id or None}, "is_error": False}
    return {"content": "", "structured_content": None, "is_error": False}
