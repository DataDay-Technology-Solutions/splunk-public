# Data Heartbeat for Splunk

**Detect when your source types stop sending data — before someone else does.**

Data Heartbeat monitors the freshness of every source type ingested by your Splunk environment, flags stalled feeds against configurable thresholds, and gives you an audit trail of every gap and recovery.

---

## What it does

- **Continuous gap detection** — schedules a saved search that compares last-seen timestamps against per-sourcetype thresholds.
- **Importance-aware alerting** — mark sourcetypes as `critical`, `high`, `medium`, or VIP. Status thresholds and alert routing key off importance, not just last-seen age.
- **Discovery catalog** — built-in catalog of well-known critical sourcetypes (CrowdStrike, Okta, Palo Alto, AWS CloudTrail, Azure AD, etc.) so you can opt in to monitoring with one click.
- **Audit history** — every status change, every threshold edit, every VIP toggle is recorded to a KV-store-backed audit log.
- **Alert action validation** — surface configured alert actions (email, Slack, PagerDuty, Teams, webhook, ServiceNow) and warn before you wire an alert to a misconfigured action.
- **Cloud-ready** — passes Splunk AppInspect for `cloud` + `splunk_appinspect` tags. No custom Python, no scripted inputs, no outbound HTTP from the app.

## Installation

1. Download the `.tar.gz` from Splunkbase (or this repo's release).
2. In Splunk Web → **Manage Apps → Install app from file**, upload the package, and restart Splunk if prompted.
3. Open **Apps → Data Heartbeat** to land on the Monitor view.

For Splunk Cloud (Victoria or Classic): install via Self-Service in Splunkbase or upload through Cloud Admin Console.

## First-run configuration

The app ships with all scheduled searches **disabled** so it never runs against your data without your sign-off. To turn it on:

1. Open **Settings** inside the app.
2. Adjust the default detection threshold and detection cadence.
3. Toggle **Enable Scheduled Detection**. This enables the saved search `Data Heartbeat - Source Type Monitor`.
4. (Optional) On the Monitor page, click **Discover Source Types** to scan for active sourcetypes in your environment, or open the **Catalog** tab to pick from known critical sourcetypes.

## Views

| View | Purpose |
|---|---|
| **Monitor** | Live status of every monitored sourcetype with stat cards and inline filters. |
| **Settings** | Detection cadence, default thresholds, and alert action configuration. |
| **Audit History** | Append-only log of every status change, threshold edit, and VIP/importance toggle. |

## KV Store collections

The app creates four collections on first install (no data is shipped):

- `monitored_sourcetypes` — the source-of-truth list of sourcetypes under monitoring
- `heartbeat_settings` — detection cadence, default thresholds, alert routing
- `heartbeat_audit_log` — append-only audit trail
- `discovery_sources` — catalog of where each sourcetype was discovered

## Permissions

Default permissions grant read access to all authenticated users and write access to `admin` and `sc_admin` only. To allow other roles to mark sourcetypes as VIP or change thresholds, edit the role list in **Settings**.

## Cloud compatibility

This app is validated for Splunk Cloud Victoria and Classic. It uses only:

- Simple XML dashboards (no scripted inputs, no Mako, no Django)
- Splunk's bundled jQuery + SplunkJS MVC
- KV Store collections (no custom REST endpoints)
- CSV lookups as a cold-start fallback

There are zero `.py` files in the package.

## Splunk Cloud (Victoria + Classic)

Validated against Splunk AppInspect with **all 8 tags** that matter for cloud and Splunkbase submission:
`cloud`, `splunk_appinspect`, `private_app`, `private_victoria`, `private_classic`, `packaging_standards`, `future`, `migration_victoria`.

Result: **0 failures, 0 errors, 111 successes, 116 N/A, 2 informational warnings** (SplunkJS telemetry + collections.conf usage — both safe per Splunk's own messages).

### Why this app is cloud-safe
- **No Python** — pure SimpleXML + JS + KV-store + lookups.
- **No scripted inputs**, no outbound HTTP from the app.
- **No custom REST endpoints** (removed in v1.1.0).
- **No `local/` directory** in the package.
- **No instance-wide overrides** (`web.conf` was removed in v1.1.0).
- **Discovery uses `| metadata`**, never an `index=*` event scan, so it stays well within Splunk Cloud query limits even on multi-TB tenants.

### Installation paths

| Stack | Path |
|---|---|
| **Splunk Cloud Victoria** | Self-service via Splunkbase (search "Data Heartbeat" → Install) |
| **Splunk Cloud Classic** | Splunkbase via Cloud Admin Console → Install Apps from Splunkbase |
| **Splunk Enterprise (on-prem)** | Splunkbase install OR upload `.tar.gz` via Manage Apps |
| **Splunk Free / Trial** | Same as Enterprise |

## Keyboard shortcuts

| Key | Action |
|---|---|
| `r` | Refresh dashboard |
| `d` | Run Discovery |
| `a` | Add Source Type |
| `?` | Show shortcuts toast |
| `Esc` | Close any open modal |
| `Tab` / `Shift+Tab` | Cycle focus inside modals (focus-trapped) |

Shortcuts are suppressed while focus is in an input/textarea/select.

## Permissions

- **Read access:** all authenticated users (`*`).
- **Write access:** `admin` and `sc_admin` only.

The UI hides write controls (Add, Discovery, Detection) when the current user isn't admin/sc_admin. To grant write access to other roles, update `metadata/local.meta` (on-prem) or use **Settings → User and Authentication → Roles**.

## Troubleshooting

### Dashboard shows "Loading..." forever
Browser console likely has a JS error. Common causes: KV-store collection didn't initialize (restart Splunk), or another app's CSS rule is colliding (check devtools).

### Empty dashboard with "Couldn't load source types"
1. Confirm the KV-store collection exists:
   ```
   | rest /servicesNS/nobody/SA-Data-Heartbeat/storage/collections/config | search title="monitored_sourcetypes"
   ```
2. Confirm your role has `read_collections` for it.
3. On Splunk Cloud, KV-store can be slow on first install — wait 60 seconds.

### Saved searches won't run
By design, all saved searches ship `disabled = 1, enableSched = 0`. Toggle them on from the **Settings** page or under **Settings → Searches, Reports, and Alerts**.

### Audit history feels truncated
The audit query caps at 1000 rows by default. Filter by date range in the Audit view to see older entries.

### Discovery returns no sourcetypes
- On Splunk Cloud, `| metadata` requires the user to have `search_indexes_allowed` for at least one index.
- On a fresh deployment with no data, there are no sourcetypes to discover.

### KV-store collection creation fails on first install
This is almost always a Splunk-instance issue, not the app. Check `splunkd.log` for `KVStorageProvider` errors. On Cloud, file a support ticket.

## FAQ

**Q: Does this consume a lot of search resources?**
No. The detection search runs every 5 minutes by default and uses `| metadata` (bucket-level only, not event scan). Discovery defaults to daily. Both are tunable.

**Q: Can I extend the catalog with custom sourcetypes?**
Yes. Edit `lookups/heartbeat_catalog.csv` and add rows. Format: `category,match_type,sourcetype,importance,threshold,notes`. `match_type` is `exact` or `regex`.

**Q: Will it impact ingestion?**
No. The app does not touch ingestion pipelines, `props.conf`, or `transforms.conf` for indexing. It only reads lookups and bucket metadata.

**Q: Does it work in a multi-search-head deployment?**
Yes. KV-store collections replicate via SHC. Deploy via the deployer in standard SHC fashion.

**Q: How do I integrate with PagerDuty / Slack / ServiceNow?**
Configure those alert actions on the Settings page. The app surfaces enabled/configured actions and warns if you wire an alert to one that isn't fully configured.

**Q: Can I run this against `_internal` or `_audit` indexes?**
Yes. `| metadata` reads internal indexes if your role has access.

## Screenshots

Screenshots live in `docs/screenshots/` and are referenced by the Splunkbase listing.

| Screen | File |
|---|---|
| Monitor | `docs/screenshots/monitor.png` |
| Settings | `docs/screenshots/settings.png` |
| Audit | `docs/screenshots/audit.png` |
| Onboarding banner | `docs/screenshots/onboarding.png` |
| Mobile | `docs/screenshots/mobile.png` |

## Support

- **Vendor:** DataDay Technology Solutions
- **Issues:** https://github.com/DataDay-Technology-Solutions/splunk-apps/issues
- **Email:** support@datadaytech.com

## Versioning

Semver `MAJOR.MINOR.PATCH` aligned with the `[id]` and `[launcher]` stanzas in `default/app.conf`. The `[install] build` integer increments on every release.

## License

See `LICENSE.txt`. Third-party notices in `NOTICE`.
