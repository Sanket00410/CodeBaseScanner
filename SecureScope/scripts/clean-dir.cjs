const fs = require("node:fs");
const path = require("node:path");

const target = process.argv[2];
if (!target) {
  process.exit(0);
}

const fullPath = path.resolve(process.cwd(), target);
try {
  fs.rmSync(fullPath, { recursive: true, force: true });
} catch {
  // Ignore cleanup failures.
}
