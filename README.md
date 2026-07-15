# IPAScope

iOS static security analysis that runs entirely in your browser. Drop an `.ipa` file and get a concise report — no backend required.

**Status:** v0.5.0

Live demo: https://ipascope.com


## Screenshots

Dark theme

![IPAScope - Dark](docs/screenshots/landing-dark.png)

Light theme

![IPAScope - Light](docs/screenshots/landing-light.png)


## What it does

- Parses the bundle and Mach-O executable to extract headers and flags.
- Extracts and parses embedded provisioning profiles and entitlements.
- Runs pattern-based secret detection (vendor regexes + entropy gating).
- Performs ATS/TLS checks per-domain and reports risks.
- Produces exportable reports: PDF, JSON, CSV, SARIF.


## Quick Start

1. Open locally (no build step):

   - macOS: `open index.html`
   - Windows: `start index.html`
   - Linux: `xdg-open index.html`

2. Or serve a local server (enables Web Worker):

   ```bash
   python3 -m http.server 8000
   # Visit http://localhost:8000
   ```

3. Or deploy as a static site (GitHub Pages / Netlify / Cloudflare Pages).


## Notes

- Files are analyzed entirely in the browser; nothing is uploaded.
- On `file://` the Web Worker may fall back to main-thread parsing.
- This tool is meant as a fast, static first-pass scanner — not a replacement for dynamic analysis.


## Contributing

- Open issues or PRs on GitHub. If you add tests or refactors, keep changes minimal and focused.


## Authors

Uday Shelke & Saurabh Sanmane


## License

MIT
