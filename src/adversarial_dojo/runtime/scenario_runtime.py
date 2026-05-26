from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adversarial_dojo.records import LeakEvent, RuntimeEvent, ToolCallRecord
from adversarial_dojo.scenario import Scenario, ToolResult
from adversarial_dojo.runtime.canaries import CanaryRegistry
from adversarial_dojo.runtime.leaks import LeakDetector
from adversarial_dojo.runtime.resources import ResourceStore
from adversarial_dojo.runtime.tool_impl import ToolImplExecutor


class ScenarioRuntime:
    def __init__(
        self,
        scenario: Scenario,
        *,
        state: dict[str, Any] | None = None,
        events_path: str | Path | None = None,
    ) -> None:
        self.scenario = scenario
        self.canaries = CanaryRegistry(scenario.canaries)
        self.resource_store = ResourceStore(scenario.resources)
        self.leak_events: list[LeakEvent] = []
        self.tool_calls: list[ToolCallRecord] = []
        self.events_path = Path(events_path) if events_path is not None else None
        self.leak_detector = LeakDetector(scenario, self.canaries)
        self.executor = ToolImplExecutor(
            scenario.tool_impls,
            timeout_seconds=scenario.tool_timeout_seconds,
        )
        if state is not None:
            self._load_state(state)
        if self.events_path is not None:
            self.events_path.parent.mkdir(parents=True, exist_ok=True)

    def invoke(self, tool: str, arguments: dict[str, Any] | None = None) -> ToolCallRecord:
        original_args = arguments or {}
        self._record_event("tool_request", {"tool": tool, "arguments": original_args})
        self.scenario.tool_interface.find_tool(tool)
        new_leaks = self._check_leaks(tool, original_args)
        remasked_args = self.canaries.remask(original_args)
        self.resource_store.begin_call()
        self.resource_store.add_available_placeholders(
            self.canaries.placeholders_in(remasked_args)
        )
        try:
            template_result = self.executor.invoke(tool, remasked_args, self.resource_store)
        except Exception as exc:
            template_result = ToolResult(content=str(exc), is_error=True)
            self._record_event(
                "tool_error",
                {"tool": tool, "error": f"{type(exc).__name__}: {exc}"},
            )
        self._validate_response_placeholders(template_result)
        result = ToolResult(
            content=self.canaries.substitute(template_result.content),
            structured_content=self.canaries.substitute(template_result.structured_content),
            is_error=template_result.is_error,
        )
        self._validate_result_size(result)
        observed_now = self.canaries.mark_observed_from_response(
            {
                "content": result.content,
                "structured_content": result.structured_content,
            }
        )
        call = ToolCallRecord(
            tool=tool,
            arguments=original_args,
            result_content=result.content,
            structured_content=result.structured_content,
            is_error=result.is_error,
        )
        self.tool_calls.append(call)
        self._record_event(
            "tool_response",
            {
                "tool": tool,
                "observed_canaries": sorted(observed_now),
                "leaks": [event.model_dump(mode="json") for event in new_leaks],
                "result": result.model_dump(mode="json"),
            },
        )
        return call

    @property
    def success(self) -> bool:
        return bool(self.leak_events)

    def state_snapshot(self) -> dict[str, Any]:
        return {
            "resources": self.resource_store.snapshot(),
            "observed_canaries": sorted(self.canaries.observed),
            "leak_events": [event.model_dump(mode="json") for event in self.leak_events],
        }

    @classmethod
    def from_state_file(
        cls,
        scenario: Scenario,
        *,
        state_path: str | Path,
        events_path: str | Path | None = None,
    ) -> ScenarioRuntime:
        path = Path(state_path)
        state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
        return cls(scenario, state=state, events_path=events_path)

    def write_state_file(self, state_path: str | Path) -> None:
        path = Path(state_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.state_snapshot(), indent=2) + "\n", encoding="utf-8")

    def _load_state(self, state: dict[str, Any]) -> None:
        self.resource_store = ResourceStore.from_snapshot(state.get("resources", []))
        self.canaries.observed = set(state.get("observed_canaries", []))
        self.leak_events = [
            LeakEvent.model_validate(item) for item in state.get("leak_events", [])
        ]

    def _check_leaks(self, tool: str, original_args: dict[str, Any]) -> list[LeakEvent]:
        events = self.leak_detector.check(
            tool=tool,
            original_args=original_args,
            observed_canaries=set(self.canaries.observed),
        )
        self.leak_events.extend(events)
        for event in events:
            self._record_event("leak", event.model_dump(mode="json"))
        return events

    def _validate_response_placeholders(self, result: ToolResult) -> None:
        response_placeholders = self.canaries.placeholders_in(
            {
                "content": result.content,
                "structured_content": result.structured_content,
            }
        )
        unknown = response_placeholders - self.canaries.known_ids()
        if unknown:
            raise ValueError(
                "tool response referenced unknown canary placeholders: "
                + ", ".join(sorted(unknown))
            )
        unavailable = response_placeholders - self.resource_store.available_placeholders
        if unavailable:
            raise ValueError(
                "tool response fabricated unavailable canary placeholders: "
                + ", ".join(sorted(unavailable))
            )

    def _validate_result_size(self, result: ToolResult) -> None:
        size = len(result.content)
        if result.structured_content is not None:
            size += len(_stringify(result.structured_content))
        if size > self.scenario.max_tool_result_chars:
            raise ValueError(
                f"tool result is {size} chars, max is {self.scenario.max_tool_result_chars}"
            )

    def _record_event(self, event: str, payload: dict[str, Any]) -> None:
        if self.events_path is None:
            return
        runtime_event = RuntimeEvent(event=event, payload=payload)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(runtime_event.model_dump_json() + "\n")


def _stringify(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)
