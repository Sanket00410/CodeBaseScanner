from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field


PYTHON_FAMILIES = {
    "sql-injection",
    "command-injection",
    "path-traversal",
    "insecure-deserialization",
    "unsafe-eval",
    "server-side-request-forgery",
    "open-redirect",
    "template-injection",
}
JS_FAMILIES = {"xss", "unsafe-eval", "prototype-pollution", "sql-injection", "command-injection", "path-traversal"}


@dataclass(slots=True)
class FlowMatch:
    family: str
    line_number: int
    sink: str
    source_vars: list[str] = field(default_factory=list)
    source_lines: list[int] = field(default_factory=list)
    sanitized: bool = False
    confidence: float = 0.0
    details: str = ""
    trace: list[str] = field(default_factory=list)

    def evidence_summary(self) -> str:
        parts = [f"sink={self.sink}"]
        if self.source_vars:
            parts.append(f"sources={','.join(self.source_vars)}")
        if self.source_lines:
            parts.append(f"source_lines={','.join(str(item) for item in self.source_lines)}")
        parts.append(f"sanitized={'yes' if self.sanitized else 'no'}")
        return " | ".join(parts)


@dataclass(slots=True)
class _TaintState:
    source_vars: set[str] = field(default_factory=set)
    source_lines: set[int] = field(default_factory=set)
    sanitized: bool = False
    dynamic: bool = False
    sql_like: bool = False

    def merge(self, other: _TaintState | None) -> _TaintState | None:
        if other is None:
            return self
        return _TaintState(
            source_vars=set(self.source_vars) | set(other.source_vars),
            source_lines=set(self.source_lines) | set(other.source_lines),
            sanitized=self.sanitized or other.sanitized,
            dynamic=self.dynamic or other.dynamic,
            sql_like=self.sql_like or other.sql_like,
        )


PY_SOURCE_PATTERNS = (
    "request.args",
    "request.form",
    "request.values",
    "request.get_json",
    "request.json",
    "request.query_params",
    "request.path_params",
    "request.cookies",
    "request.headers",
    "request.GET",
    "request.POST",
    "self.request.GET",
    "self.request.POST",
    "self.request.query_params",
    "self.request.path_params",
)
PY_SANITIZERS = {
    "int",
    "float",
    "bool",
    "html.escape",
    "escape",
    "markupsafe.escape",
    "bleach.clean",
    "django.utils.html.escape",
    "django.utils.http.url_has_allowed_host_and_scheme",
    "fastapi.encoders.jsonable_encoder",
    "shlex.quote",
    "urllib.parse.quote",
    "werkzeug.utils.secure_filename",
    "os.path.basename",
}
PY_REDIRECT_SANITIZERS = {
    "url_has_allowed_host_and_scheme",
    "django.utils.http.url_has_allowed_host_and_scheme",
    "is_safe_url",
}

JS_SOURCE_RE = re.compile(
    r"\b(?:req|request|ctx|context)\.(?:query|body|params)\b|"
    r"\b(?:router|nextRouter)\.query\b|"
    r"\b(?:location|window\.location)\.(?:search|hash)\b|"
    r"\b(?:searchParams|params)\.get\s*\(|"
    r"\buseSearchParams\s*\(|"
    r"\bprops\.[A-Za-z_$][\w$]*"
)
JS_SANITIZER_RE = re.compile(
    r"\b(?:DOMPurify\.sanitize|escapeHtml|encodeURIComponent|sanitizeHtml|validator\.escape|he\.encode|xssFilters\.[A-Za-z_][\w$]*)\s*\("
)
JS_PATH_SANITIZER_RE = re.compile(r"\b(?:path\.(?:basename|normalize|resolve)|sanitizeFilename)\s*\(")
JS_ASSIGN_RE = re.compile(r"^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$")


def find_flow_match(content: str, file_suffix: str, family: str, line_number: int) -> FlowMatch | None:
    suffix = file_suffix.lower()
    if suffix == ".py":
        return _best_match(_analyze_python(content, family), line_number)
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return _best_match(_analyze_js(content, family), line_number)
    return None


def analyze_family(content: str, file_suffix: str, family: str) -> list[FlowMatch]:
    suffix = file_suffix.lower()
    if suffix == ".py":
        return _analyze_python(content, family)
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return _analyze_js(content, family)
    return []


def _best_match(matches: list[FlowMatch], line_number: int) -> FlowMatch | None:
    if not matches:
        return None
    ranked = sorted(matches, key=lambda item: (abs(item.line_number - line_number), -item.confidence))
    return ranked[0]


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return ""


def _is_request_expr(node: ast.AST) -> bool:
    text = ast.unparse(node)
    return any(pattern in text for pattern in PY_SOURCE_PATTERNS) or text.startswith("input(")


def _expr_taint(node: ast.AST | None, env: dict[str, _TaintState]) -> _TaintState | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        state = env.get(node.id)
        return (
            _TaintState(
                set(state.source_vars),
                set(state.source_lines),
                state.sanitized,
                state.dynamic,
                state.sql_like,
            )
            if state
            else None
        )
    if _is_request_expr(node):
        return _TaintState({"request_input"}, {getattr(node, "lineno", 0)}, False, False, False)
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name in PY_SANITIZERS and node.args:
            inner = _expr_taint(node.args[0], env)
            if inner:
                inner.sanitized = True
                return inner
        if name in PY_REDIRECT_SANITIZERS and node.args:
            inner = _expr_taint(node.args[0], env)
            if inner:
                inner.sanitized = True
                return inner
        combined: _TaintState | None = None
        for arg in node.args:
            state = _expr_taint(arg, env)
            if state:
                combined = state if combined is None else combined.merge(state)
        return combined
    if isinstance(node, ast.JoinedStr):
        combined: _TaintState | None = None
        sql_like = False
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                text = value.value.lower()
                sql_like = sql_like or any(keyword in text for keyword in ("select ", "insert ", "update ", "delete ", " where ", " from "))
            state = _expr_taint(value, env)
            if state:
                state.dynamic = True
                state.sql_like = state.sql_like or sql_like
                combined = state if combined is None else combined.merge(state)
        if combined:
            combined.sql_like = combined.sql_like or sql_like
        return combined
    if isinstance(node, ast.FormattedValue):
        return _expr_taint(node.value, env)
    if isinstance(node, ast.BinOp):
        left = _expr_taint(node.left, env)
        right = _expr_taint(node.right, env)
        sql_like = False
        for side in (node.left, node.right):
            if isinstance(side, ast.Constant) and isinstance(side.value, str):
                text = side.value.lower()
                sql_like = sql_like or any(keyword in text for keyword in ("select ", "insert ", "update ", "delete ", " where ", " from "))
        if left and right:
            merged = left.merge(right)
            if merged:
                merged.dynamic = True
                merged.sql_like = merged.sql_like or sql_like
            return merged
        base = left or right
        if base:
            base.dynamic = True
            base.sql_like = base.sql_like or sql_like
        return base
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        combined: _TaintState | None = None
        for element in node.elts:
            state = _expr_taint(element, env)
            if state:
                combined = state if combined is None else combined.merge(state)
        return combined
    if isinstance(node, ast.Dict):
        combined: _TaintState | None = None
        for value in node.values:
            state = _expr_taint(value, env)
            if state:
                combined = state if combined is None else combined.merge(state)
        return combined
    return None


class _PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, family: str) -> None:
        self.family = family
        self.env: dict[str, _TaintState] = {}
        self.matches: list[FlowMatch] = []

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        state = _expr_taint(node.value, self.env)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if state:
                    self.env[target.id] = state
                elif target.id in self.env:
                    del self.env[target.id]
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _call_name(node)
        if self.family == "sql-injection":
            self._maybe_sql_injection(node, name)
        elif self.family == "command-injection":
            self._maybe_command_injection(node, name)
        elif self.family == "path-traversal":
            self._maybe_path_traversal(node, name)
        elif self.family == "insecure-deserialization":
            self._maybe_deserialization(node, name)
        elif self.family == "unsafe-eval":
            self._maybe_eval(node, name)
        elif self.family == "server-side-request-forgery":
            self._maybe_ssrf(node, name)
        elif self.family == "open-redirect":
            self._maybe_open_redirect(node, name)
        elif self.family == "template-injection":
            self._maybe_template_injection(node, name)
        self.generic_visit(node)

    def _append(self, node: ast.Call, sink: str, state: _TaintState | None, confidence: float, details: str) -> None:
        if state is None:
            return
        self.matches.append(
            FlowMatch(
                family=self.family,
                line_number=getattr(node, "lineno", 1),
                sink=sink,
                source_vars=sorted(state.source_vars),
                source_lines=sorted(line for line in state.source_lines if line),
                sanitized=state.sanitized,
                confidence=confidence,
                details=details,
                trace=[details],
            )
        )

    def _maybe_sql_injection(self, node: ast.Call, name: str) -> None:
        if not name.endswith(("execute", "query", "executemany")):
            return
        first_arg = node.args[0] if node.args else None
        state = _expr_taint(first_arg, self.env)
        query_text = ast.unparse(first_arg).lower() if first_arg is not None else ""
        has_sql_keywords = any(keyword in query_text for keyword in ("select ", "insert ", "update ", "delete ", " where ", " from "))
        if state and state.dynamic and (has_sql_keywords or state.sql_like) and len(node.args) <= 1:
            confidence = 0.95 if not state.sanitized else 0.72
            self._append(node, name, state, confidence, "request input reaches dynamic SQL query construction at execution sink")

    def _maybe_command_injection(self, node: ast.Call, name: str) -> None:
        if name not in {"os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"}:
            return
        first_arg = node.args[0] if node.args else None
        state = _expr_taint(first_arg, self.env)
        shell_true = any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords)
        if state and (shell_true or state.dynamic or name == "os.system"):
            confidence = 0.94 if shell_true and not state.sanitized else 0.74
            self._append(node, name, state, confidence, "request input reaches shell/command execution sink")

    def _maybe_path_traversal(self, node: ast.Call, name: str) -> None:
        if name not in {"open", "send_file"}:
            return
        first_arg = node.args[0] if node.args else None
        state = _expr_taint(first_arg, self.env)
        if state:
            confidence = 0.88 if not state.sanitized else 0.62
            self._append(node, name, state, confidence, "request-controlled path reaches filesystem access sink")

    def _maybe_deserialization(self, node: ast.Call, name: str) -> None:
        if name not in {"pickle.loads", "yaml.load"}:
            return
        first_arg = node.args[0] if node.args else None
        state = _expr_taint(first_arg, self.env)
        if state:
            confidence = 0.92 if not state.sanitized else 0.68
            self._append(node, name, state, confidence, "untrusted input reaches unsafe deserialization sink")

    def _maybe_eval(self, node: ast.Call, name: str) -> None:
        if name not in {"eval", "exec"}:
            return
        first_arg = node.args[0] if node.args else None
        state = _expr_taint(first_arg, self.env)
        if state:
            confidence = 0.93 if not state.sanitized else 0.7
            self._append(node, name, state, confidence, "request-controlled expression reaches dynamic execution sink")

    def _maybe_ssrf(self, node: ast.Call, name: str) -> None:
        if name not in {"requests.get", "requests.post", "requests.request", "httpx.get", "httpx.post", "httpx.request", "urlopen", "urllib.request.urlopen"}:
            return
        target = node.args[0] if node.args else None
        if target is None:
            for keyword in node.keywords:
                if keyword.arg in {"url", "uri"}:
                    target = keyword.value
                    break
        state = _expr_taint(target, self.env)
        if state:
            confidence = 0.9 if not state.sanitized else 0.68
            self._append(node, name, state, confidence, "request-controlled URL reaches outbound HTTP sink")

    def _maybe_open_redirect(self, node: ast.Call, name: str) -> None:
        if name not in {"redirect", "flask.redirect", "HttpResponseRedirect", "RedirectResponse"}:
            return
        target = node.args[0] if node.args else None
        state = _expr_taint(target, self.env)
        if state:
            confidence = 0.87 if not state.sanitized else 0.64
            self._append(node, name, state, confidence, "request-controlled redirect target reaches response redirect sink")

    def _maybe_template_injection(self, node: ast.Call, name: str) -> None:
        first_arg = node.args[0] if node.args else None
        state: _TaintState | None = None
        if name == "render_template_string":
            state = _expr_taint(first_arg, self.env)
        elif name.endswith(".render") and isinstance(node.func, ast.Attribute):
            template_owner = node.func.value
            if isinstance(template_owner, ast.Call):
                owner_name = _call_name(template_owner)
                if owner_name.endswith("Template"):
                    template_state = _expr_taint(template_owner.args[0] if template_owner.args else None, self.env)
                    state = template_state
        if state:
            confidence = 0.89 if not state.sanitized else 0.66
            self._append(node, name, state, confidence, "request-controlled template content reaches server-side template rendering sink")


def _analyze_python(content: str, family: str) -> list[FlowMatch]:
    if family not in PYTHON_FAMILIES:
        return []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    analyzer = _PythonAnalyzer(family)
    analyzer.visit(tree)
    return analyzer.matches


def _expr_has_source(expr: str, env: dict[str, _TaintState]) -> _TaintState | None:
    if JS_SOURCE_RE.search(expr):
        return _TaintState({"request_input"}, set(), False, False)
    combined: _TaintState | None = None
    for var_name, state in env.items():
        if re.search(rf"\b{re.escape(var_name)}\b", expr):
            copied = _TaintState(set(state.source_vars), set(state.source_lines), state.sanitized, True)
            combined = copied if combined is None else combined.merge(copied)
    if JS_SANITIZER_RE.search(expr) and combined:
        combined.sanitized = True
    if JS_PATH_SANITIZER_RE.search(expr) and combined:
        combined.sanitized = True
    return combined


def _analyze_js(content: str, family: str) -> list[FlowMatch]:
    if family not in JS_FAMILIES:
        return []
    env: dict[str, _TaintState] = {}
    matches: list[FlowMatch] = []
    lines = content.splitlines()
    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        assign = JS_ASSIGN_RE.match(line)
        if assign:
            name, expr = assign.groups()
            state = _expr_has_source(expr, env)
            if state:
                state.source_lines.add(idx)
                state.source_vars.add(name)
                env[name] = state
            elif name in env:
                del env[name]

        if family == "xss":
            sink_patterns = [
                ("innerHTML", r"\.innerHTML\s*=\s*(.+)$"),
                ("document.write", r"document\.write\s*\((.+)\)"),
                ("dangerouslySetInnerHTML", r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(.+?)\s*\}\s*\}"),
            ]
        elif family == "sql-injection":
            sink_patterns = [
                ("db.query", r"(?:db|pool|client|connection|sequelize)\.(?:query|execute)\s*\((.+)\)"),
                ("prisma.$queryRaw", r"prisma\.\$queryRaw(?:Unsafe)?\s*\((.+)\)"),
            ]
        elif family == "command-injection":
            sink_patterns = [
                ("child_process.exec", r"(?:child_process\.)?(?:exec|execSync)\s*\((.+)\)"),
                ("child_process.spawn", r"(?:child_process\.)?(?:spawn|spawnSync)\s*\((.+)\)"),
            ]
        elif family == "path-traversal":
            sink_patterns = [
                ("fs.readFile", r"(?:fs\.)?(?:readFile|readFileSync|writeFile|writeFileSync|open|createReadStream|createWriteStream)\s*\((.+)\)"),
            ]
        elif family == "unsafe-eval":
            sink_patterns = [
                ("eval", r"\beval\s*\((.+)\)"),
                ("new Function", r"new\s+Function\s*\((.+)\)"),
            ]
        else:
            sink_patterns = [
                ("Object.assign", r"Object\.assign\s*\(\s*\{\s*\}\s*,\s*(.+)\)"),
                ("merge", r"\b(?:merge|deepmerge|lodash\.merge|_\.merge)\s*\((.+)\)"),
            ]

        for sink, pattern in sink_patterns:
            match = re.search(pattern, line)
            if not match:
                continue
            state = _expr_has_source(match.group(1), env)
            if state:
                if family == "sql-injection":
                    lowered = match.group(1).lower()
                    if not any(token in lowered for token in ("select ", "insert ", "update ", "delete ", " where ", " from ", "${", "+")):
                        continue
                confidence = 0.9 if not state.sanitized else 0.68
                matches.append(
                    FlowMatch(
                        family=family,
                        line_number=idx,
                        sink=sink,
                        source_vars=sorted(state.source_vars),
                        source_lines=sorted(line for line in state.source_lines if line),
                        sanitized=state.sanitized,
                        confidence=confidence,
                        details="request-controlled data reaches JavaScript sink",
                        trace=[f"{','.join(sorted(state.source_vars)) or 'request_input'} -> {sink}"],
                    )
                )
    return matches
