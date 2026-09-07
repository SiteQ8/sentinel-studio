# Sentinel Studio

Sentinel Studio is a polished, static cybersecurity assessment reporting dashboard. It helps authorized teams organize findings, communicate risk, model conceptual attack paths, and export a printable assessment record—without sending assessment data to a server.

> **Demonstration notice:** The included Northstar engagement, assets, evidence, coverage, and findings are entirely fictional sample data. Sentinel Studio does not scan targets, run exploits, validate vulnerabilities, or independently verify security controls.

## Features

- Executive risk summary, severity distribution, and remediation progress
- Searchable and filterable findings register
- Detailed impact, evidence, remediation, and reference views
- Create, edit, and delete custom findings saved to browser `localStorage`
- Scope, rules of engagement, and asset inventory views
- Interactive, educational attack-path visualization
- Plain-language security knowledge cards
- Validated JSON export/import (2 MB import limit)
- Print-optimized assessment report
- Responsive layout and basic keyboard/accessibility support
- No build process, analytics, network requests, or runtime dependencies

## Run locally

No installation or build is required. Open `index.html` directly in a modern browser, or serve the directory with any static HTTP server.

For example, if an HTTP server is already available on your machine:

```sh
cd sentinel-studio
npx serve .
```

`npx` is not a project dependency; it is only one optional way to serve static files. Direct file access works for core features.

## Data and privacy

Findings are stored under the `sentinel-studio-findings-v1` key in the current browser's local storage. Data does not leave the browser unless the user explicitly exports a JSON file or prints the report. Clearing site data removes custom records. Export important work regularly.

Imported files must contain either a Sentinel Studio export object with a `findings` array or a findings array. Records are schema-checked before import. Treat exported reports as potentially sensitive and protect them according to your organization's policies.

## GitHub Pages

GitHub Pages is configured for branch-based publishing from the `main` branch at the repository root. The pre-rendered content in `index.html` ensures the executive summary, findings register, and educational views remain useful as a static page.

Some GitHub connector safety layers may filter script elements while writing a remote `index.html`. If the deployed page is missing its script include, the page will remain a polished static report but interactive filtering, local storage, import/export, and dialogs will not be enabled. The repository owner should add a normal deferred script element that loads `app.js` immediately before the closing body tag in the remote `index.html`.

The local project intentionally retains its existing `app.js` script tag.

## Security and appropriate use

Use Sentinel Studio only to document work you are authorized to perform. It contains no active scanner or exploit capability. See [SECURITY.md](SECURITY.md) for vulnerability reporting and security design notes.

## Browser support

Current versions of Chrome, Edge, Firefox, and Safari are recommended. The application uses native HTML dialogs, CSS custom properties, local storage, and standard browser file APIs.

## License

Released under the [MIT License](LICENSE).