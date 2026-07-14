# Changelog

## v0.4.0 — Liquid Glass Redesign

A full visual redesign, not a recolor. New palette, new hero structure, new
card system, dead code from three design iterations finally cleaned out.

**Palette**
- Graphite backgrounds (`#09090B` / `#111113` / `#18181B`) replacing the
  near-black/blue scheme.
- Orange accent (`#FF9F0A` / `#FFB340`) replacing blue throughout — buttons,
  tags, score rings, badges, PDF export branding.
- Glass surfaces: `rgba(255,255,255,.04–.06)` backgrounds + `backdrop-filter:
  blur(28px)` on every floating panel (cards, tabs, export dropdown, modal,
  header) — not just a translucent color, actual frosted glass.
- Light theme redone to match: frosted white glass instead of solid white cards.

**Hero — rebuilt, not restyled**
- Two-panel layout: left = title/tagline/description/CTAs, right = Finder-style
  dropzone + a floating glass **IPA Loaded** summary panel.
- Removed the fake rotating vulnerability-finding preview (`PREVIEW_SAMPLES`,
  `setupPreviewRotator`) — replaced with a static, realistic app summary
  (App Name, Bundle ID, iOS Version, SwiftUI, Mach-O, ATS, Entitlements, Score).
  No JS timer needed for it anymore.
- Removed cursor-tracking spotlight (`setupCursorSpot`) and the three colored
  mesh orbs — replaced with one subtle centered radial glow + a near-invisible
  grid, per "very subtle radial light, almost invisible grid."
- Dropzone: rotating `conic-gradient` border and terminal-style traffic-light
  chrome removed. Now a plain 32px-radius glass panel with a cloud-upload icon
  and "Drag .ipa Here / or / Browse Files."
- Rainbow animated gradient title text removed — solid accent color, static.

**Cards**
- `stat-card`, `results-section`, `finding-card`, `permission-item`, export
  dropdown, tabs, and the share modal all moved to the shared glass treatment:
  28px radius, `rgba(255,255,255,.08)` border, `0 25px 70px rgba(0,0,0,.22)` shadow.
- Removed severity-coded left borders on finding cards — severity is
  conveyed by the existing badge/pill, so nothing was lost, just decluttered.

**Header**
- Removed the "APK Auditor" / "ADB Auditor" sibling pills.
- Added a Documentation link and GitHub link pointed at
  `github.com/sudouday/ipascope`; footer, structured data (`creator`), and
  `<meta name="author">` updated to match — the old repo/owner references
  were left pointing at the previous project's author, which would've been a
  visible inconsistency next to the new links.

**Cleanup**
- Removed dead CSS/markup carried over from earlier iterations that the
  redesign made irrelevant: unused `.hero-badge`/`pulse` keyframe, unused
  `.gradient-orbs`/`.grid-pattern` divs (already `display:none`), the unused
  `.serif`/Fraunces font import (never referenced in markup), leftover
  `@property --rotation-angle` from the removed border animation.
- Retinted app icons (favicon, 192/512/maskable) and `theme-color` meta tags
  from blue to the new graphite/orange palette — previously only the page
  body was rebranded, not the icons.

**Unchanged**
- Scan engine, MITRE/CWE/SwiftUI detection, share backend, export formats —
  none of that logic was touched, only presentation.

## v0.3.0 — Optional Share-Report Backend

Added a backend — but scoped to one job, and off by default, so it doesn't
quietly break the "100% client-side, nothing leaves the tab" promise the rest
of this project makes.

**Added**
- `server/` — a zero-npm-dependency Node backend (just `http`, `fs`, `crypto`)
  that stores a scan report under a random ID and serves it back, so a result
  can be turned into a link. See `server/README.md` for run/deploy/config.
- `src/core/config.js` — `API_BASE` constant, empty by default. Empty = Share
  is disabled and the app is unchanged from v0.2.x: fully static, no backend
  contacted, ever. Only set this if you've deployed `server/`.
- New **Share Link** export option, alongside PDF/JSON/CSV/SARIF. Sends only
  the in-memory findings/summary/score object — never the original `.ipa` or
  its raw bytes (those were never held in memory as a full blob to begin with,
  and the raw Mach-O load-command dump plus file tree are stripped before send).
- Share modal shows the link (copy button) and a one-time delete token (also
  copyable) so the person who shared it can revoke early. The server only
  ever stores a hash of that token, not the token itself.
- Opening a `?report=<id>` link loads and renders that report read-only, with
  a dismissible banner. File Explorer and re-scan naturally have nothing to
  show for a shared report, since raw bytes were never sent — that's by
  design, not a bug.
- Reports auto-expire after 30 days (configurable), cleaned up on an interval.
- Rate-limited (20 POSTs/hour/IP default) and size-capped (2MB default) to
  keep the unauthenticated write endpoint from being an easy abuse target.

**Fixed during this milestone, before shipping**
- Oversized-payload rejection (413) was silently swallowed: destroying the
  socket mid-stream to enforce the size cap also killed the response, so the
  client only ever saw a dangling `100 Continue` and never the actual 413.
  Caught by testing the failure path with curl, not just the happy path.
  Fixed by checking `Content-Length` upfront and, for the streaming fallback,
  draining to `end` instead of destroying the socket before a response could
  be written.
- Verified end-to-end with curl: create → fetch → wrong-token delete (403) →
  correct-token delete (200) → confirm gone (404) → rate-limit trip (429).

## v0.2.1 — Bundle Detection Fix

**Fixed**
- `.app` bundle detection was anchored to the absolute root of the zip (`^Payload/...`),
  so any IPA with an extra wrapping folder, a lowercase `payload/`, or no `Payload/`
  wrapper at all (some non-Xcode packaging tools zip the `.app` directly) failed with
  "No .app bundle found in IPA" even though the bundle was right there.
- Now matches `Payload/Name.app/` anywhere in the path (not just at position 0),
  preserves the actual casing found instead of hardcoding `Payload/`, and falls back
  to locating any `*.app/` directory containing `Info.plist` when there's no
  `Payload/` wrapper.
- Failure message (when it's genuinely not an IPA) now lists the top-level entries
  it found, so you can tell "wrong file" from "bug" without opening dev tools.
- Verified against four synthetic zip shapes (normal, wrapped, lowercase, bare) before packaging.

## v0.2.0 — MITRE ATT&CK + SwiftUI Detection

CWE mapping already existed per-rule from v1; this milestone adds ATT&CK and SwiftUI.

**Added**
- MITRE ATT&CK Mobile mapping on 30+ existing rules plus 3 analyzer-native findings
  (`prov_get_task_allow`, `database_files`, `cert_files`), verified against the live
  Mobile matrix (attack.mitre.org, v19) rather than assumed from memory.
  - Vulnerability-class findings link to the offensive technique an attacker would use
    (e.g. clipboard access → T1414, cleartext HTTP → T1638 Adversary-in-the-Middle).
  - `secure` findings (Keychain, SSL pinning, jailbreak/anti-debug detection, file
    protection, biometrics) are tagged `(mitigates)` against the technique they defend
    against, shown in green instead of orange in the UI.
  - Findings with no clean 1:1 Mobile-matrix match (e.g. localhost URLs, S3 bucket
    refs) intentionally carry no `mitre` field rather than forcing a bad mapping.
- Findings UI: new `ATT&CK` tag per finding, linking straight to `attack.mitre.org/techniques/<ID>/`
  (sub-techniques resolve correctly, e.g. `T1636.003` → `.../T1636/003/`).
- MITRE technique IDs are now searchable in the findings filter box.
- MITRE field threaded through JSON, CSV, SARIF, and PDF exports.
- SwiftUI detection: two new rules —
  - `swiftui_detected` (info): `import SwiftUI`, `@State`/`@ObservedObject`/`@EnvironmentObject`,
    `SwiftUICore`/`_SwiftUI` binary symbols, `: View {` conformance.
  - `appstorage_detected` (warning, CWE-312, T1409): flags `@AppStorage`, since it persists
    to `UserDefaults` under the hood — same plaintext-on-disk exposure as `NSUserDefaults`,
    just easy to miss because it looks like a SwiftUI-native API.

**Fixed**
- Regex bug in the new rules: `\b` doesn't match immediately before `@` (both are
  non-word-adjacent to whitespace), so `\b@State\b` silently matched nothing. Caught
  by smoke-testing before packaging, not shipped broken.

**Unchanged**
- CWE mapping (was already present per-rule in the inherited engine, not new this milestone).
- Scan pipeline, Mach-O/provisioning/ATS parsing, export formats, UI shell from v0.1.0.

**Planned next (v0.3.0)** — pick one: dashboard security-score/severity charts,
`core/` restructure into parser/scanners/rules/exports, or continue hardening detections.

## v0.1.0 — Foundation & Rebrand

This is milestone 1: the project renamed and reskinned, running on the proven
IPA Auditor engine underneath. No scanning logic changed — this milestone is
UI/branding only, per plan.

**Added**
- Rebranded to IPAScope (title, meta tags, manifest strings, JS namespace `IPAA` → `IPAS`).
- New logo mark: scope/target ring, used in the header, favicon, and app icons (192/512/maskable).
- Apple-inspired color retint: system blue accent (`#2997FF` dark / `#0071E3` light),
  system green/red/orange for status colors, matching Apple's HIG palette.
- Font stack now prioritizes `-apple-system` / `SF Pro` before falling back to Inter for non-Apple devices.
- `CNAME` updated to `ipascope.com`; `robots.txt` / `sitemap.xml` domain updated.

**Unchanged (carried over as-is, working)**
- Mach-O parser, provisioning profile / CMS extractor, plist parser, ATS analyzer,
  entropy + secret detection, rule engine, PDF/JSON/CSV/SARIF export, Web Worker pipeline.
- Folder layout (`src/core/*`) — deeper modularization into `core/parser`, `core/scanners`,
  `core/rules`, `core/exports` is planned for v0.2 so it can be done without breaking
  the worker message contract in the same pass as new features.

**Planned next (v0.2.0)**
- MITRE ATT&CK mapping on findings
- CWE mapping alongside existing MASVS mapping
- SwiftUI detection (binary + framework heuristics)
- Begin `core/` restructure into parser / scanners / rules / exports modules

**Known limitation**
- Dashboard security-score visualization, severity pie chart, and diff-two-IPAs are
  not in this milestone — flagging so it's not mistaken for scope creep quietly dropped.
