from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any

from google.protobuf import descriptor_pb2

from adversarial_dojo.models import MockEnvironment, MockMcpServer, MockTool


def load_proto_tool_surface(path: str | Path) -> MockEnvironment:
    proto_path = Path(path)
    descriptor_set = _compile_proto(proto_path)
    messages = _message_index(descriptor_set)
    enums = _enum_index(descriptor_set)

    servers: list[MockMcpServer] = []
    for file_descriptor in descriptor_set.file:
        package = file_descriptor.package
        for service in file_descriptor.service:
            tools: list[MockTool] = []
            for method in service.method:
                input_message = messages[method.input_type]
                tools.append(
                    MockTool(
                        name=_to_snake_case(method.name),
                        description=f"{service.name}.{method.name}",
                        args_schema=_message_to_schema(input_message, messages, enums),
                    )
                )
            servers.append(MockMcpServer(name=_service_name(package, service.name), tools=tools))
    if not servers:
        raise ValueError(f"proto tool surface must define at least one service: {proto_path}")
    return MockEnvironment(mcp_servers=servers)


def _compile_proto(proto_path: Path) -> descriptor_pb2.FileDescriptorSet:
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "surface.pb"
        args = [
            f"--proto_path={proto_path.parent}",
            f"--descriptor_set_out={output_path}",
            "--include_imports",
            str(proto_path),
        ]
        try:
            from grpc_tools import protoc

            import grpc_tools

            include_path = Path(grpc_tools.__file__).parent / "_proto"
            result = protoc.main(["protoc", f"--proto_path={include_path}", *args])
            if result != 0:
                raise ValueError(f"protoc failed with exit code {result}: {proto_path}")
        except ImportError:
            completed = subprocess.run(
                ["protoc", *args],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                raise ValueError(f"protoc failed for {proto_path}: {completed.stderr.strip()}")
        descriptor_set = descriptor_pb2.FileDescriptorSet()
        descriptor_set.ParseFromString(output_path.read_bytes())
        return descriptor_set


def _message_index(
    descriptor_set: descriptor_pb2.FileDescriptorSet,
) -> dict[str, descriptor_pb2.DescriptorProto]:
    messages: dict[str, descriptor_pb2.DescriptorProto] = {}
    for file_descriptor in descriptor_set.file:
        package_prefix = f".{file_descriptor.package}" if file_descriptor.package else ""
        for message in file_descriptor.message_type:
            _collect_messages(messages, package_prefix, message)
    return messages


def _collect_messages(
    messages: dict[str, descriptor_pb2.DescriptorProto],
    prefix: str,
    message: descriptor_pb2.DescriptorProto,
) -> None:
    full_name = f"{prefix}.{message.name}" if prefix else f".{message.name}"
    messages[full_name] = message
    for nested in message.nested_type:
        _collect_messages(messages, full_name, nested)


def _enum_index(
    descriptor_set: descriptor_pb2.FileDescriptorSet,
) -> dict[str, descriptor_pb2.EnumDescriptorProto]:
    enums: dict[str, descriptor_pb2.EnumDescriptorProto] = {}
    for file_descriptor in descriptor_set.file:
        package_prefix = f".{file_descriptor.package}" if file_descriptor.package else ""
        for enum in file_descriptor.enum_type:
            enums[f"{package_prefix}.{enum.name}" if package_prefix else f".{enum.name}"] = enum
        for message in file_descriptor.message_type:
            _collect_enums(enums, package_prefix, message)
    return enums


def _collect_enums(
    enums: dict[str, descriptor_pb2.EnumDescriptorProto],
    prefix: str,
    message: descriptor_pb2.DescriptorProto,
) -> None:
    message_prefix = f"{prefix}.{message.name}" if prefix else f".{message.name}"
    for enum in message.enum_type:
        enums[f"{message_prefix}.{enum.name}"] = enum
    for nested in message.nested_type:
        _collect_enums(enums, message_prefix, nested)


def _message_to_schema(
    message: descriptor_pb2.DescriptorProto,
    messages: dict[str, descriptor_pb2.DescriptorProto],
    enums: dict[str, descriptor_pb2.EnumDescriptorProto],
) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    required: list[str] = []
    map_entries = {nested.name: nested for nested in message.nested_type if nested.options.map_entry}
    for field in message.field:
        properties[field.name] = _field_to_schema(field, messages, enums, map_entries)
        if _is_required(field, messages):
            required.append(field.name)
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return schema


def _field_to_schema(
    field: descriptor_pb2.FieldDescriptorProto,
    messages: dict[str, descriptor_pb2.DescriptorProto],
    enums: dict[str, descriptor_pb2.EnumDescriptorProto],
    map_entries: dict[str, descriptor_pb2.DescriptorProto],
) -> dict[str, Any]:
    if field.label == descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED:
        map_entry = map_entries.get(field.type_name.rsplit(".", 1)[-1])
        if map_entry is not None and field.type == descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE:
            value_field = next(nested_field for nested_field in map_entry.field if nested_field.name == "value")
            return {"type": "object", "additionalProperties": _field_to_schema(value_field, messages, enums, {})}
        item_field = descriptor_pb2.FieldDescriptorProto()
        item_field.CopyFrom(field)
        item_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
        return {"type": "array", "items": _field_to_schema(item_field, messages, enums, {})}

    scalar = _scalar_schema(field.type)
    if scalar is not None:
        return scalar
    if field.type == descriptor_pb2.FieldDescriptorProto.TYPE_ENUM:
        enum = enums[field.type_name]
        return {"type": "string", "enum": [value.name for value in enum.value]}
    if field.type == descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE:
        if field.type_name in {".google.protobuf.Struct"}:
            return {"type": "object", "additionalProperties": True}
        if field.type_name in {".google.protobuf.Value"}:
            return {}
        if field.type_name in {".google.protobuf.ListValue"}:
            return {"type": "array", "items": {}}
        return _message_to_schema(messages[field.type_name], messages, enums)
    return {}


def _scalar_schema(proto_type: int) -> dict[str, str] | None:
    scalar_types = descriptor_pb2.FieldDescriptorProto
    if proto_type in {
        scalar_types.TYPE_DOUBLE,
        scalar_types.TYPE_FLOAT,
    }:
        return {"type": "number"}
    if proto_type in {
        scalar_types.TYPE_INT64,
        scalar_types.TYPE_UINT64,
        scalar_types.TYPE_INT32,
        scalar_types.TYPE_FIXED64,
        scalar_types.TYPE_FIXED32,
        scalar_types.TYPE_UINT32,
        scalar_types.TYPE_SFIXED32,
        scalar_types.TYPE_SFIXED64,
        scalar_types.TYPE_SINT32,
        scalar_types.TYPE_SINT64,
    }:
        return {"type": "integer"}
    if proto_type == scalar_types.TYPE_BOOL:
        return {"type": "boolean"}
    if proto_type == scalar_types.TYPE_STRING:
        return {"type": "string"}
    if proto_type == scalar_types.TYPE_BYTES:
        return {"type": "string", "contentEncoding": "base64"}
    return None


def _is_required(
    field: descriptor_pb2.FieldDescriptorProto,
    messages: dict[str, descriptor_pb2.DescriptorProto],
) -> bool:
    if field.label == descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED:
        return False
    if field.proto3_optional:
        return False
    if field.type == descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE:
        message = messages.get(field.type_name)
        return bool(message and message.options.map_entry)
    return True


def _service_name(package: str, service_name: str) -> str:
    del package
    return _to_snake_case(service_name)


def _to_snake_case(value: str) -> str:
    chars: list[str] = []
    for index, char in enumerate(value):
        if char.isupper() and index > 0 and (not value[index - 1].isupper()):
            chars.append("_")
        chars.append(char.lower())
    return "".join(chars)
