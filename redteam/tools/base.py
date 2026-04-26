"""Minimal tool base class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ToolResult:
    output: str
    is_error: bool = False


class BaseTool(ABC):
    name: str
    description: str
    input_schema: dict[str, Any]  # JSON Schema for parameters

    @abstractmethod
    async def execute(self, arguments: dict[str, Any]) -> ToolResult: ...

    def to_api_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }
