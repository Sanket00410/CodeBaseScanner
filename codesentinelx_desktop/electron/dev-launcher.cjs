const { spawn } = require("node:child_process");
const path = require("node:path");

// Some Windows environments persist this variable globally, which forces
// Electron to run as plain Node and breaks app startup.
delete process.env.ELECTRON_RUN_AS_NODE;

const electronBinary = require("electron");
const mainEntry = path.resolve(__dirname, "..", "dist-main", "electron", "main.js");

const child = spawn(electronBinary, [mainEntry], {
  stdio: "inherit",
  env: { ...process.env },
});

child.on("error", (error) => {
  console.error("Failed to launch Electron:", error);
  process.exit(1);
});

child.on("exit", (code) => {
  process.exit(code ?? 0);
});
