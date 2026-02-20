from __future__ import annotations

from universal_security_scanner.plugins.builtin.go_plugin import GoSecurityPlugin
from universal_security_scanner.plugins.builtin.javascript_plugin import JavaScriptSecurityPlugin
from universal_security_scanner.plugins.builtin.python_plugin import PythonSecurityPlugin
from universal_security_scanner.plugins.sdk.interfaces import BaseLanguagePlugin


def load_builtin_language_plugins() -> list[BaseLanguagePlugin]:
    return [
        PythonSecurityPlugin(),
        JavaScriptSecurityPlugin(),
        GoSecurityPlugin(),
    ]
