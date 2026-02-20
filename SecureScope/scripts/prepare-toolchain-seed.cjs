const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const secureScopeRoot = path.resolve(__dirname, "..");
const scannerRoot = path.resolve(secureScopeRoot, "..");
const outputDir = path.join(secureScopeRoot, "build", "toolchain-seed");
const buildCacheDir = path.join(secureScopeRoot, "build", ".toolchain-build");
const envSeed = process.env.CODESENTINELX_TOOLCHAIN_SEED;
const workspaceSeed = path.resolve(scannerRoot, ".toolchain");
const bundleConfigPath = path.join(secureScopeRoot, "build", "toolchain-bundle.windows-x64.json");
const strictMode = String(process.env.CODESENTINELX_BUNDLE_STRICT || "0").toLowerCase() === "1";
const rebuildBundle = String(process.env.CODESENTINELX_REBUILD_BUNDLED_TOOLCHAIN || "0").toLowerCase() === "1";

function hasEntries(dir) {
  try {
    return fs.readdirSync(dir).length > 0;
  } catch {
    return false;
  }
}

function resetDir(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  } catch {
    // Best-effort stale directory fallback for locked files on Windows.
    try {
      if (fs.existsSync(dir)) {
        const staleDir = `${dir}.stale-${Date.now()}`;
        fs.renameSync(dir, staleDir);
      }
    } catch {
      // Ignore stale rename failures.
    }
  }
  fs.mkdirSync(dir, { recursive: true });
}

function resolvePythonExecutable() {
  const envPython = process.env.CODESENTINELX_PYTHON;
  if (envPython && fs.existsSync(envPython)) {
    return envPython;
  }
  const candidates = [
    path.join(scannerRoot, ".venv", "Scripts", "python.exe"),
    path.join(scannerRoot, ".venv", "bin", "python"),
    "python",
  ];
  for (const candidate of candidates) {
    if (candidate === "python" || fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return "python";
}

function loadBundleConfig() {
  if (!fs.existsSync(bundleConfigPath)) {
    return {
      profile: "fallback",
      bundled_tools: ["semgrep", "trivy", "gitleaks", "codeql", "bandit", "nuclei"],
      not_bundleable_on_windows: [],
    };
  }
  return JSON.parse(fs.readFileSync(bundleConfigPath, "utf-8"));
}

function parseBootstrapStatus(stdout) {
  const lines = String(stdout || "").split(/\r?\n/);
  const ok = [];
  const missing = [];
  const pattern = /^\[(OK|MISSING)\]\s+([^\s|]+)\s+\|/i;
  for (const line of lines) {
    const match = line.trim().match(pattern);
    if (!match) {
      continue;
    }
    const marker = String(match[1] || "").toUpperCase();
    const name = String(match[2] || "").trim();
    if (!name) {
      continue;
    }
    if (marker === "OK") {
      ok.push(name);
    } else {
      missing.push(name);
    }
  }
  return { ok, missing };
}

function pruneHeavyArtifacts(dir) {
  const archiveRegex = /\.(zip|tar|gz|tgz|txz|xz|sig|asc|sha1|sha256|pem)$/i;
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
        continue;
      }
      if (archiveRegex.test(entry.name)) {
        fs.rmSync(fullPath, { force: true });
      }
    }
  }
}

function writeManifest(payload) {
  const manifestPath = path.join(outputDir, "BUNDLE_MANIFEST.json");
  fs.writeFileSync(manifestPath, `${JSON.stringify(payload, null, 2)}\n`, "utf-8");
}

function getExistingManifest() {
  try {
    const raw = fs.readFileSync(path.join(outputDir, "BUNDLE_MANIFEST.json"), "utf-8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function resolveFastSeedSource() {
  const candidates = [envSeed, workspaceSeed].filter(Boolean).map((item) => path.resolve(item));
  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && hasEntries(candidate)) {
      return candidate;
    }
  }
  return "";
}

function canReuseExistingSeed(source, profile) {
  if (!fs.existsSync(outputDir) || !hasEntries(outputDir)) {
    return false;
  }
  const manifest = getExistingManifest();
  if (!manifest) {
    return false;
  }
  return (
    String(manifest.mode || "") === "fast-seed-copy" &&
    path.resolve(String(manifest.fallback_source || "")) === path.resolve(source) &&
    String(manifest.profile || "") === String(profile || "")
  );
}

function runBootstrapBuild(config) {
  const tools = (config.bundled_tools || []).filter(Boolean);
  if (tools.length === 0) {
    return { success: false, reason: "No bundled tools configured.", ok: [], missing: [] };
  }

  resetDir(buildCacheDir);

  const python = resolvePythonExecutable();
  const args = [
    "-m",
    "universal_security_scanner.cli",
    "bootstrap-tools",
    "--path",
    scannerRoot,
    "--tools",
    tools.join(","),
  ];

  const env = {
    ...process.env,
    USS_TOOLS_DIR: buildCacheDir,
    USS_AUTO_BOOTSTRAP_TOOLS: "1",
    USS_ALLOW_HOST_INSTALLERS: "0",
    USS_PREFER_LOCAL_TOOLS: "1",
    PYTHONUTF8: "1",
  };

  const result = spawnSync(python, args, {
    cwd: scannerRoot,
    env,
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });

  const stdout = String(result.stdout || "");
  const stderr = String(result.stderr || "");
  const parsed = parseBootstrapStatus(stdout);
  const success = (result.status === 0 || result.status === 2) && hasEntries(buildCacheDir) && parsed.ok.length > 0;

  return {
    success,
    status: result.status,
    signal: result.signal,
    stdout,
    stderr,
    ok: parsed.ok,
    missing: parsed.missing,
    reason: success ? "" : `Bootstrap command failed or produced empty cache (status=${result.status}).`,
  };
}

function seedFromExistingCandidates() {
  const source = resolveFastSeedSource();
  if (!source) {
    return { seeded: false, source: "" };
  }
  resetDir(outputDir);
  fs.cpSync(source, outputDir, { recursive: true, force: true });
  return { seeded: true, source };
}

const config = loadBundleConfig();
if (!rebuildBundle) {
  const fastSource = resolveFastSeedSource();
  if (fastSource && canReuseExistingSeed(fastSource, config.profile || "windows-x64-default")) {
    console.log(`[toolchain-seed] Reusing existing bundled seed from ${fastSource}`);
    process.exit(0);
  }
  const fastSeed = seedFromExistingCandidates();
  if (fastSeed.seeded) {
    pruneHeavyArtifacts(outputDir);
    writeManifest({
      generated_at: new Date().toISOString(),
      profile: config.profile || "windows-x64-default",
      mode: "fast-seed-copy",
      fallback_source: fastSeed.source,
      bundled_tools_requested: config.bundled_tools || [],
      bundled_tools_ready: [],
      missing_tools: [],
      not_bundleable_on_windows: config.not_bundleable_on_windows || [],
    });
    console.log(`[toolchain-seed] Fast seed copied from ${fastSeed.source}`);
    process.exit(0);
  }
}

const bundleRun = runBootstrapBuild(config);
resetDir(outputDir);

if (bundleRun.success) {
  fs.cpSync(buildCacheDir, outputDir, { recursive: true, force: true });
  pruneHeavyArtifacts(outputDir);
  writeManifest({
    generated_at: new Date().toISOString(),
    profile: config.profile || "windows-x64-default",
    mode: "built-during-package",
    bundled_tools_requested: config.bundled_tools || [],
    bundled_tools_ready: bundleRun.ok,
    missing_tools: bundleRun.missing,
    not_bundleable_on_windows: config.not_bundleable_on_windows || [],
  });
  console.log(`[toolchain-seed] Built bundled toolchain from source with ${bundleRun.ok.length} ready tools.`);
  if (bundleRun.missing.length > 0) {
    console.log(`[toolchain-seed] Missing during build: ${bundleRun.missing.join(", ")}`);
  }
} else {
  console.log(`[toolchain-seed] Dynamic bundle build failed: ${bundleRun.reason}`);
  if (bundleRun.stderr) {
    console.log(`[toolchain-seed] stderr: ${bundleRun.stderr.trim()}`);
  }

  const fallback = seedFromExistingCandidates();
  if (fallback.seeded) {
    pruneHeavyArtifacts(outputDir);
    writeManifest({
      generated_at: new Date().toISOString(),
      profile: config.profile || "windows-x64-default",
      mode: "fallback-seed-copy",
      fallback_source: fallback.source,
      bundled_tools_requested: config.bundled_tools || [],
      bundled_tools_ready: [],
      missing_tools: [],
      not_bundleable_on_windows: config.not_bundleable_on_windows || [],
    });
    console.log(`[toolchain-seed] Fallback seeded from ${fallback.source}`);
  } else {
    const notePath = path.join(outputDir, "README.txt");
    fs.writeFileSync(
      notePath,
      [
        "No toolchain seed could be generated during packaging.",
        "Installer will bootstrap tools at first launch using local-only policy.",
      ].join("\n"),
      "utf-8",
    );
    writeManifest({
      generated_at: new Date().toISOString(),
      profile: config.profile || "windows-x64-default",
      mode: "empty-placeholder",
      bundled_tools_requested: config.bundled_tools || [],
      bundled_tools_ready: [],
      missing_tools: [],
      not_bundleable_on_windows: config.not_bundleable_on_windows || [],
    });
    console.log("[toolchain-seed] No fallback seed found. Placeholder generated.");
  }

  if (strictMode) {
    process.exit(1);
  }
}
