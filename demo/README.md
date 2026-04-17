# CodeSentinelX Demo UI

Standalone web demo for presenting CodeSentinelX role-based scans and reports.

## What it shows

- Admin, Security Analyst, Developer, Auditor, and Management views
- Role-specific tool scope
- Severity distribution
- Report previews for Combined, Vulnerability, Fixes, Existing, and Management
- Board-friendly charts and developer-friendly findings

## Zero-install fallback

Open `standalone-demo.html` directly in any browser. No npm install required.

## Presentation mode

For a cleaner live demo, open:

```text
standalone-demo.html?present=1
```

Then click **Enter Fullscreen** or press **F11**.

Presentation mode hides the left navigation and gives the demo a more deck-like executive layout.

## Run the React version

```powershell
cd demo
npm install
npm run dev
```

## Build

```powershell
cd demo
npm run build
```
