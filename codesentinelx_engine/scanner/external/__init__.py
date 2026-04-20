"""External scanner integrations for enterprise coverage."""

from __future__ import annotations

from importlib import import_module
from typing import Any

__all__ = [
    "all_tool_names",
    "discover_toolchain",
    "external_tool_names",
    "get_tool_entry",
    "prepare_toolchain",
    "run_external_runtime_tool",
    "run_external_tool",
    "supported_runner_tools",
    "tool_metadata",
    "tool_names_for_target",
    "ToolStatus",
]


_ATTR_TO_MODULE = {
    "all_tool_names": "codesentinelx_engine.scanner.external.catalog",
    "get_tool_entry": "codesentinelx_engine.scanner.external.catalog",
    "tool_names_for_target": "codesentinelx_engine.scanner.external.catalog",
    "external_tool_names": "codesentinelx_engine.scanner.external.registry",
    "run_external_runtime_tool": "codesentinelx_engine.scanner.external.registry",
    "run_external_tool": "codesentinelx_engine.scanner.external.registry",
    "supported_runner_tools": "codesentinelx_engine.scanner.external.registry",
    "tool_metadata": "codesentinelx_engine.scanner.external.registry",
    "discover_toolchain": "codesentinelx_engine.scanner.external.toolchain",
    "prepare_toolchain": "codesentinelx_engine.scanner.external.toolchain",
    "ToolStatus": "codesentinelx_engine.scanner.external.toolchain",
}


def __getattr__(name: str) -> Any:
    module_name = _ATTR_TO_MODULE.get(name)
    if not module_name:
        raise AttributeError(name)
    module = import_module(module_name)
    return getattr(module, name)
