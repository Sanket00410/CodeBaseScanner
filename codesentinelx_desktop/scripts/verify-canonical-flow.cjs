const { execFileSync } = require("node:child_process");

const steps = [
  ["npm", ["run", "typecheck"]],
  ["npm", ["run", "build:main"]],
  ["npm", ["run", "test:projection"]],
  ["npm", ["run", "build:renderer"]],
];

for (const [command, args] of steps) {
  const label = `${command} ${args.join(" ")}`;
  console.log(`\n[verify:canonical-flow] ${label}`);
  execFileSync(command, args, {
    cwd: process.cwd(),
    stdio: "inherit",
    shell: process.platform === "win32",
  });
}

console.log("\n[verify:canonical-flow] completed successfully");
