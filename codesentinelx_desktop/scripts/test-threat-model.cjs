const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { ThreatModelService } = require(path.join(__dirname, "..", "dist-main", "backend", "threatModelService.js"));

async function main() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "codesentinelx-threat-model-"));
  const outputRoot = fs.mkdtempSync(path.join(os.tmpdir(), "codesentinelx-threat-model-out-"));

  fs.mkdirSync(path.join(tempRoot, "frontend", "src"), { recursive: true });
  fs.mkdirSync(path.join(tempRoot, "backend"), { recursive: true });

  fs.writeFileSync(
    path.join(tempRoot, "frontend", "src", "App.tsx"),
    [
      'import React from "react";',
      "export default function App() {",
      '  return <button onClick={() => window.open("/api/export")}>Export</button>;',
      "}",
      "",
    ].join("\n"),
    "utf8",
  );

  fs.writeFileSync(
    path.join(tempRoot, "backend", "app.py"),
    [
      "from fastapi import FastAPI",
      "app = FastAPI()",
      "",
      '@app.get("/api/health")',
      "def health():",
      '    return {"ok": True}',
      "",
      '@app.post("/api/auth/login")',
      "def login():",
      '    return {"token": "demo"}',
      "",
    ].join("\n"),
    "utf8",
  );

  try {
    const service = new ThreatModelService(outputRoot);
    const result = await service.createThreatModel({
      projectPath: tempRoot,
      requestedBy: "local-user",
      framework: "STRIDE",
    });

    assert.equal(result.report.schema_version, "codesentinelx.threat_model.v1");
    assert.ok(result.report.entry_points.length > 0, "expected threat model entry points");
    assert.ok(result.report.threats.length > 0, "expected threat model threats");
    assert.ok(fs.existsSync(result.jsonPath), "expected JSON artifact");
    assert.ok(fs.existsSync(result.htmlPath), "expected HTML artifact");
    assert.ok(fs.existsSync(result.mermaidPath), "expected Mermaid artifact");

    const json = JSON.parse(fs.readFileSync(result.jsonPath, "utf8"));
    assert.equal(json.diagram.includes("flowchart TD"), true);

    console.log(
      JSON.stringify(
        {
          target: result.report.target_path,
          sourceFiles: result.report.summary.source_files_analyzed,
          entryPoints: result.report.summary.entry_points,
          threats: result.report.summary.threats,
        },
        null,
        2,
      ),
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    fs.rmSync(outputRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
