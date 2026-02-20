"""External scanner integrations for enterprise coverage."""

from universal_security_scanner.scanner.external.catalog import all_tool_names, get_tool_entry, tool_names_for_target
from universal_security_scanner.scanner.external.registry import (
    external_tool_names,
    run_external_runtime_tool,
    run_external_tool,
    supported_runner_tools,
    tool_metadata,
)
from universal_security_scanner.scanner.external.toolchain import ToolStatus, discover_toolchain, prepare_toolchain

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
