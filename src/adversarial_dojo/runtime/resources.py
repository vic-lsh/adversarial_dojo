from __future__ import annotations

import json
from typing import Any

from adversarial_dojo.scenario import AccessPolicy, ResourceSpec, find_canary_placeholders


class ResourceStore:
    def __init__(self, resources: list[ResourceSpec]) -> None:
        self._resources = {resource.id: resource.model_copy(deep=True) for resource in resources}
        self._available_placeholders: set[str] = set()

    def begin_call(self) -> None:
        self._available_placeholders = set()

    @property
    def available_placeholders(self) -> set[str]:
        return set(self._available_placeholders)

    def add_available_placeholders(self, placeholders: set[str]) -> None:
        self._available_placeholders.update(placeholders)

    def get_resource(self, resource_id: str) -> ResourceSpec | None:
        resource = self._resources.get(resource_id)
        if resource is None:
            return None
        self._record_read(resource)
        return resource.model_copy(deep=True)

    def find_resource_by_identifier(self, key: str, value: Any) -> ResourceSpec | None:
        for resource in self._resources.values():
            if resource.identifiers.get(key) == value:
                self._record_read(resource)
                return resource.model_copy(deep=True)
        return None

    def search_resources(
        self,
        query: str = "",
        *,
        kind: str | None = None,
    ) -> list[ResourceSpec]:
        lowered_query = query.lower()
        matches: list[ResourceSpec] = []
        for resource in self._resources.values():
            if kind is not None and resource.kind != kind:
                continue
            haystack = _stringify(
                {
                    "id": resource.id,
                    "kind": resource.kind,
                    "content": resource.content,
                    "identifiers": resource.identifiers,
                }
            ).lower()
            if lowered_query and lowered_query not in haystack:
                continue
            self._record_read(resource)
            matches.append(resource.model_copy(deep=True))
        return matches

    def create_resource(
        self,
        resource_id: str,
        *,
        kind: str,
        content: Any = "",
        identifiers: dict[str, Any] | None = None,
        access: AccessPolicy | dict[str, Any] | None = None,
    ) -> ResourceSpec:
        if resource_id in self._resources:
            raise ValueError(f"resource already exists: {resource_id}")
        if access is None:
            access_policy = AccessPolicy(readers=["victim"], writers=["victim"])
        elif isinstance(access, AccessPolicy):
            access_policy = access
        else:
            access_policy = AccessPolicy.model_validate(access)
        resource = ResourceSpec(
            id=resource_id,
            kind=kind,
            content=content,
            identifiers=identifiers or {},
            access=access_policy,
        )
        self._resources[resource_id] = resource
        return resource.model_copy(deep=True)

    def update_resource(self, resource_id: str, content: Any) -> ResourceSpec:
        resource = self._require_resource(resource_id)
        updated = resource.model_copy(update={"content": content}, deep=True)
        self._resources[resource_id] = updated
        return updated.model_copy(deep=True)

    def append_resource(self, resource_id: str, value: Any) -> ResourceSpec:
        resource = self._require_resource(resource_id)
        if isinstance(resource.content, list):
            content = [*resource.content, value]
        elif resource.content in ("", None):
            content = [value]
        else:
            content = [resource.content, value]
        updated = resource.model_copy(update={"content": content}, deep=True)
        self._resources[resource_id] = updated
        return updated.model_copy(deep=True)

    def snapshot(self) -> list[dict[str, Any]]:
        return [
            resource.model_dump(mode="json")
            for resource in sorted(self._resources.values(), key=lambda item: item.id)
        ]

    @classmethod
    def from_snapshot(cls, snapshot: list[dict[str, Any]]) -> ResourceStore:
        return cls([ResourceSpec.model_validate(item) for item in snapshot])

    def _require_resource(self, resource_id: str) -> ResourceSpec:
        resource = self._resources.get(resource_id)
        if resource is None:
            raise ValueError(f"unknown resource: {resource_id}")
        return resource

    def _record_read(self, resource: ResourceSpec) -> None:
        self._available_placeholders.update(
            find_canary_placeholders(resource.model_dump(mode="json"))
        )


def _stringify(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)
