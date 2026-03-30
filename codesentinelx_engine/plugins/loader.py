from __future__ import annotations

from codesentinelx_engine.plugins.builtin.go_plugin import GoSecurityPlugin
from codesentinelx_engine.plugins.builtin.javascript_plugin import JavaScriptSecurityPlugin
from codesentinelx_engine.plugins.builtin.python_plugin import PythonSecurityPlugin
from codesentinelx_engine.plugins.sdk.interfaces import BaseLanguagePlugin


def load_builtin_language_plugins() -> list[BaseLanguagePlugin]:
    return [
        PythonSecurityPlugin(),
        JavaScriptSecurityPlugin(),
        GoSecurityPlugin(),
    ]

