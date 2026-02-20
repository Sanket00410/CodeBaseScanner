const { execSync } = require("node:child_process");

function killPort(port) {
  try {
    if (process.platform === "win32") {
      const cmd =
        `powershell -NoProfile -Command "` +
        `$conns = Get-NetTCPConnection -LocalPort ${port} -ErrorAction SilentlyContinue;` +
        `if ($conns) {` +
        `$conns | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object {` +
        `Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue` +
        `}` +
        `}` +
        `"`;
      execSync(cmd, { stdio: "ignore" });
      return;
    }

    try {
      const pidList = execSync(`lsof -ti tcp:${port}`, { stdio: ["ignore", "pipe", "ignore"] }).toString();
      for (const pid of pidList.split(/\r?\n/).filter(Boolean)) {
        try {
          process.kill(Number(pid), "SIGKILL");
        } catch {
          // Ignore processes that already exited.
        }
      }
    } catch {
      // Ignore when no process owns the port.
    }
  } catch {
    // Ignore best-effort cleanup failure.
  }
}

const port = process.argv[2];
if (!port || !/^\d+$/.test(port)) {
  process.exit(0);
}
killPort(port);
