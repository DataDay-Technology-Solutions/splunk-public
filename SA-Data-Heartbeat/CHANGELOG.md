# Changelog

All notable changes to SA-Data-Heartbeat are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

## [v1.2.3] - 2026-05-18

This release is a hardening pass driven by a multi-pass bug audit. Every fix in this changelog corresponds to a verified, reproducible defect — no speculative changes.

### Fixed — Alert dispatcher (server-side, `bin/heartbeat_dispatch.py`)
- **Email alert path was broken out of the box.** Dispatcher called splunkd at `https://localhost:8089` with strict cert verification — splunkd's default self-signed cert caused `SSL: CERTIFICATE_VERIFY_FAILED` on every email dispatch. Now uses a dedicated, scoped no-verify SSL context **only** for the localhost splunkd loopback (the session key already authenticates us); all external webhook traffic still uses strict verification.
- **Non-URL alert targets crashed the dispatcher.** Typing a Slack channel name like `#security` into the per-row config would hit `urllib.request.urlopen('#security')` and throw `unknown url type` mid-loop. Dispatcher now validates http(s) scheme up front and logs `invalid webhook url` instead of crashing.
- **Exception logs lost row context.** `dispatcher exception: <error>` didn't identify which row failed. Each future is now mapped back to its work item so logs read `dispatcher exception for splunkd/slack: ...`.
- **SPL injection risk in email path.** Email recipients are now validated against a strict email regex (rejects quotes, pipes, backslashes, parens, dollar signs, backticks, control chars); sourcetype/importance/threshold values interpolated into the `| sendemail` SPL string are also sanitized as defense-in-depth.
- **Throttle held the lock during sleep**, serializing entire worker pools instead of just spacing dispatches. Throttle now computes the wake time inside the lock and releases it before sleeping.
- **Email path had no retries** while `_post_json` retried 3× — a transient REST blip would lose the alert. Email path now retries 5xx responses and network errors with exponential backoff.
- **User-Agent header was hardcoded to `SA-Data-Heartbeat/1.2.2`** even after version bumps. Dispatcher now reads the version from `default/app.conf` at startup.
- **Empty tokens in comma-split actions** (`email,,slack`) produced an empty action that logged as `unknown action ''`. Now filtered out cleanly.

### Fixed — REST admin handler (`bin/heartbeat_admin.py`)
- **Privilege escalation / SSRF via admin endpoint.** `/services/data_heartbeat/admin` had `requireAuthentication=true` but no capability gate — any authenticated user (incl. the default `user` role) could toggle scheduled-search state via `enable_all`/`disable_all`, or trigger arbitrary outbound HTTP POSTs through the dispatcher via `test_alert` (SSRF probe of internal hosts, bandwidth funnel). Handler now requires at least one of `edit_search_scheduler` or `admin_all_objects` for all three actions, matching Splunk's own RBAC for these operations.
- **Tempdir leak on test_alert.** Every "Send Test Alert" button click leaked a `/tmp/hb_test_*` directory. Now wrapped in `try/finally + shutil.rmtree`.

### Fixed — Saved searches (`default/savedsearches.conf`)
- **Detection Stalled (monitor-the-monitor) never fired.** SPL parsed `last_actual_run_time` only as ISO-8601 (`%Y-%m-%dT%H:%M:%S%z`), but `| rest` returns this field in different formats across Splunk versions: ISO-8601 on 9.x, space-delimited `2026-05-18 12:34:56 UTC` on 10.x, epoch on some Cloud builds. `strptime` returned null and the `where last_run_age_min > 15` filter dropped every row, so the meta-monitor was silently dead. SPL now coalesces all known formats — verified all three parse to the same epoch.
- **Alert search flooded notifications.** No suppression/throttle was configured, so a persistently-flagged sourcetype re-fired every 10 minutes forever (Slack/Teams/email storm until the upstream feed was fixed). Added `alert.suppress = 1`, `alert.suppress.period = 1h`, `alert.suppress.fields = sourcetype` so each flagged sourcetype only pages once an hour.
- **CSV→KV Migration could clobber live data.** Stanza shipped `disabled=0`, meaning a Splunk Manager admin could click "Run" and overwrite live KV rows (including user-edited importance/notes/alert_action) with the bundled CSV seed. Now ships `disabled=1`; the JS dashboard still seeds via direct SPL when (and only when) the KV collection is empty, so the user-facing path is unchanged.
- **"Restore from Backup" had no validation and could clobber live data.** Stanza shipped `disabled=0` with `inputlookup monitored_sourcetypes_backup.csv | outputlookup ...` — if the backup file was empty, partially written, or corrupted, the restore would upsert garbage into KV. Now ships `disabled=1`, requires `sourcetype` to be non-null/non-empty per row, and adds a `_backup_row_count > 0` guard to bail out on an empty backup.
- **Detection threshold comparison was defensively coerced to numeric.** Splunk's `eval` auto-coerces numeric-looking strings in modern releases, but `tonumber(threshold_minutes)` is now explicit so misconfigured rows can't trigger a lexical comparison silently.

### Fixed — Dashboard JS (`appserver/static/js/heartbeat-v15.js`)
- **"Run Detection Now" wrote to the wrong lookup after KV migration.** Function hardcoded `monitored_sourcetypes_csv` for both read and write — but the live source-of-truth is the KV-store collection `monitored_sourcetypes_lookup` after first-install migration. Detection results landed in the dead CSV; dashboard read from KV; status never updated. Now uses `LOOKUP_FILE` (KV) on both sides.
- **"Run Detection Now" required accelerated data models.** Used `tstats summariesonly=t` which silently returns empty on non-accelerated environments — every sourcetype would get flagged with `last_seen=0`. Now uses `| metadata type=sourcetypes index=* OR index=_*`, matching the scheduled Detection search (no event scans, no DM dependency, includes internal indexes).
- **"Run Detection Now" had no in-flight guard.** Two concurrent calls (button-click + bulk-add success + curated-pick success) raced on `outputlookup`. Now serialized via a module-level flag; duplicate callers skip cleanly and pick up the in-flight run's refresh.
- **Stored XSS in alert-action badges.** Per-row `alert_action` value was interpolated raw into `data-current="..."` and only `"` was escaped in the `title` attribute. An admin with KV write access (or the auto-discovery saved search on a hostile sourcetype-name extraction) could inject `onmouseover=` via a `<`, `>`, `&`, or `'` character. All attribute values now go through `esc()` (5-char HTML escape) and the action class is whitelisted against known action types so an unknown value can't smuggle CSS selectors.

### Changed
- **Slack target placeholder/hint no longer suggests channel names.** The per-row picker previously offered `#security-alerts` with hint "Channel name or webhook URL" — but channel names don't work; only incoming-webhook URLs do. Placeholder is now `https://hooks.slack.com/services/T0/B0/...` with a hint that explicitly rules out channel names.

### Fixed — second audit pass
- **Sourcetype picker dropdown silently hid internal sourcetypes.** `SourceTypeDiscovery.getAvailableSourceTypes` used `| metadata index=*`, which excludes `_*` indexes — so `splunkd`, `_audit`, `_internal`, etc. never appeared in the "Add Sourcetype → From environment" picker even though they're legitimate things to monitor. Same bug in `runDiscovery` (the toolbar's Run Discovery button). Both now use `index=* OR index=_*`, matching Detection.
- **Threshold field accepted `NaN` and persisted it.** A non-numeric paste into a row's threshold input wrote the literal string "NaN" into the KV-store collection. Every subsequent Detection run's `tonumber("NaN")` returned null and the row's status got stuck forever. Now range-checked client-side (`isNaN || < 1 → reject`; clamp at one year) before SPL composition.
- **Stored XSS via the settings lookup.** `displayCurrentSettings` rendered raw `setting_value` (and `setting_name` key) values into the settings summary table — an admin-controlled lookup is still XSS, and the table includes anything that ends up in `heartbeat_settings.csv` via direct edit or future code. All three columns (`key`, value, description) now go through `escapeHtml()`.
- **Stored XSS via the alert-actions lookup display.** The "enabled / configured alert actions" summary rows also rendered action-type names raw. Now escaped, matching the rest of the table.
- **Toggle handler silently reported success when it couldn't verify state.** `enableSearchByName`'s verify-state GET error handler was `function () { callback(null); }` — splunkd returning 500 / timing out / refusing the verify GET was treated as success. The user saw a green toast even though the real state was unknown. Now surfaces the verification error so the toast/error UI can drive a retry.
- **Settings page accepted invalid Slack/Teams/webhook target URLs.** `validateActionItem` only checked "non-empty" — a user could save `#general` as the global Slack target, see "Configured" in the UI, and only discover at first alert that the dispatcher rejects it. Now an http(s) URL regex check fires alongside the empty-check, with the missing-field error string explaining the expected format.
- **`Shortcuts` keydown handler didn't ignore key auto-repeat.** Holding `r` (refresh) spammed `refreshData()` many times per second and flooded splunkd. Now skips events with `e.repeat = true`.
- **Audit-log search had no watchdog timeout.** A slow / hung splunkd would leave the `AuditLogger.log` SearchManager open forever, leaking memory and search slots. Added a 30s watchdog (mirrors the Settings page pattern) plus `search:fail` handling.
- **Duplicate element IDs in `monitor.xml`.** Both the close-X button and the footer Cancel button in the VIP-confirm modal carried `id="btn-cancel-vip"` (same in the action-config modal). Invalid HTML5 + accessibility tools confused. Close-X is now a class-based handler; only the Cancel button keeps the ID.
- **`updateActionBar()` was wired to DOM elements that no longer exist.** `#btn-save-settings`, `#btn-discard-settings`, `#settings-status-text` were removed from `settings.xml` when the page moved to per-control auto-save in v1.2.0, but the JS still targeted them — all `prop()` / `text()` calls silently no-op'd. Reduced to an explicit no-op shim with a comment so the call sites don't break and the misleading code is gone.

## [v1.2.0] - 2026-05-05

### Added
- **Quick start onboarding** — single button on the welcome banner adds 10 critical security/identity/cloud/network sourcetypes from the catalog, so the dashboard isn't empty after install.
- **Keyboard shortcuts** — `r` refresh, `d` discover, `a` add, `?` help. Shown on the help toast. Suppressed inside form fields.
- **Focus trap in modals** — Escape closes; Tab/Shift+Tab cycle without escaping the dialog. Modals now have proper `role="dialog"` + `aria-modal` + `aria-hidden`.
- **Permission-aware UI** — `/services/authentication/current-context` is queried on load; write controls are hidden for users not in `admin`/`sc_admin`.
- **Skip-to-content link** for keyboard users.
- **Tooltips** on all action buttons describe what they do and the keyboard shortcut.
- **README**: Splunk Cloud (Victoria + Classic) section, Troubleshooting, FAQ, Keyboard shortcuts, Permissions, Screenshots layout.
- `docs/screenshots/` directory with capture spec.
- `app.manifest` declares `commonInformationModels: { Splunk_SA_CIM: "5.x" }` and adds Security/Fraud category for Splunkbase listing.
- HeartbeatUtils module expanded: `debounce`, `FocusTrap`, `Permissions`, `Shortcuts`.

### Changed
- **Performance**: detection saved search and discovery flow now use `| metadata type=sourcetypes` instead of `tstats count where index=*`. Drops bucket-only metadata reads instead of event scans, so it's safe on multi-TB tenants.
- **Code consolidation**: `settings.js` and `heartbeat.js` no longer have their own Toast implementations; both delegate to `HeartbeatUtils.Toast` (with safe fallback shims if utils.js fails to load).
- Table headers got `scope="col"` for screen reader column-association.
- Inline error state shown in monitor when sourcetype lookup fails (instead of just a toast).

### Removed
- `appserver/static/js/audit.js` (dead code — never referenced).
- `default/data/ui/views/audit_history.xml` (duplicate of `audit.xml`).
- ~600 lines of duplicated Toast/escape logic across the JS bundle.

### Fixed
- Audit query now caps at 1000 rows after sort (capped earlier in the pipeline so big histories don't choke).
- `escapeString` failures with backslashes inside notes/sourcetype names (audit log composition).

## [v1.1.1] - 2026-05-04

### Added
- `lookups/heartbeat_catalog.csv` — sourcetype catalog now lives in a CSV lookup instead of being hardcoded in JavaScript. New connectors can be added without an app release.
- `appserver/static/js/utils.js` — shared `Toast`, `escapeString`, and `Storage` helpers extracted from the three view scripts to remove duplication.
- Onboarding banner on the Monitor view when no sourcetypes are being monitored — points users at Discovery and Catalog.
- Pre-populated `monitored_sourcetypes.csv` with a small set of common defaults so the dashboard isn't blank on first install.
- Mobile responsive media queries in `heartbeat.css` (stacking columns under 768px).
- `prefers-reduced-motion` support — pulse and slide animations now respect user preference.
- `aria-label` attributes on key SVG icons for screen-reader accessibility.
- Filter state persistence — Monitor view filters survive page reloads via `localStorage`.
- Audit view pagination — capped at 1000 rows with a date-range picker so the table stays responsive on long histories.
- KV-store accelerated indexes on `sourcetype` for faster lookups as the collection grows.

### Changed
- Hardened `escapeString()` to handle backslashes, newlines, and other edge cases that previously could break audit log composition.
- Audit view now defaults to a 7-day window with an inline date-range picker.

### Fixed
- Several CSS duplications collapsed (`.settings-section`).
- Pulse animation no longer runs for users with `prefers-reduced-motion: reduce`.

## [v1.1.0] - 2026-05-04

### Removed
- Freemium licensing system (license validator, tier manager, REST handler, tier_gate.js, dataday.conf, restmap.conf).
- Splunk-Cloud blockers: `default/web.conf`, `metadata/local.meta`, `static/appIcon.svg`.

### Added
- `LICENSE.txt`, `NOTICE`, `README.md`, `app.manifest` for Splunkbase compliance.
- `[id]` stanza in `app.conf` for modern semver compliance.
- DiscoveryCatalog feature: visual catalog of known critical sourcetypes (security, identity, network, cloud).

### Changed
- `version` 1.0.0 → 1.1.0, `build` 32 → 34.
- AppInspect now passes with 0 failures, 0 errors against `cloud` + `splunk_appinspect` + `private_app` + `private_victoria` + `private_classic` + `packaging_standards` + `future` + `migration_victoria` tags.

## [v1.0.0] - prior

Initial development releases (built up to build 32 on `splunk-apps-dev`). See git history before commit `1d794ff` for details.
