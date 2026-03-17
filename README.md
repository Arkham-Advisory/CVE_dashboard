# CVE Dashboard

A frontend-only web application that converts raw AWS vulnerability reports into readable dashboards, prioritized findings, and executive-ready reports.

## Features

- **Upload**: Drag & drop CSV or XLSX vulnerability reports
- **Auto-detection**: Automatically detects CVE columns and maps report schemas
- **Dashboard**: KPI cards, severity distribution chart, top CVEs and affected assets
- **Findings Explorer**: Full TanStack Table with sorting, filtering, and pagination
- **CVE Detail Drawer**: Click any CVE to see full details, affected assets, and packages
- **Report View**: Print-ready executive summary with full appendix

## Tech Stack

- React 18 + TypeScript + Vite
- Tailwind CSS + shadcn/ui primitives
- TanStack Table v8
- Zustand (state management)
- PapaParse (CSV parsing)
- SheetJS/xlsx (XLSX parsing)
- Recharts (charts)
- React Router (HashRouter for static hosting)

## Development

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
```

Output is in `./dist/`.

## Deployment

The app is deployed to GitHub Pages at `https://Arkham-Advisory.github.io/CVE_dashboard/`.

Deployment is automated via GitHub Actions on every push to `main`.

To enable GitHub Pages:
1. Go to repo **Settings → Pages**
2. Set source to **GitHub Actions**

## Supported File Formats

- `.csv` — parsed with PapaParse
- `.xlsx` / `.xls` — parsed with SheetJS

Column detection is automatic. The parser looks for columns containing `CVE-YYYY-NNNNN` patterns and heuristically maps severity, asset, package, and version columns.
