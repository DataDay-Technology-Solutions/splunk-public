# DataDay Tech — Public Splunk Apps

Public-facing distribution for Splunk apps maintained by [DataDay Technology Solutions](https://datadaytech.com).

This repository mirrors the AppInspect-clean release artifacts of our apps. Each app's directory contains exactly what ships on Splunkbase — no dev scripts, no test fixtures, no runtime state. Download the precompiled tarball from the [Releases](https://github.com/DataDay-Technology-Solutions/splunk-public/releases) page for the version of any app.

## Apps

### SA-Data-Heartbeat — `v1.2.3`

Monitor source types for data gaps. Detects when source types stop logging, flags them based on configurable thresholds, and dispatches per-row notifications via email, Slack, Teams, or generic webhook.

- Source: [`SA-Data-Heartbeat/`](./SA-Data-Heartbeat)
- Changelog: [`SA-Data-Heartbeat/CHANGELOG.md`](./SA-Data-Heartbeat/CHANGELOG.md)
- Tarball: [Releases → v1.2.3](https://github.com/DataDay-Technology-Solutions/splunk-public/releases/tag/v1.2.3)
- Splunkbase: (pending listing)

**Requirements**: Splunk Enterprise 9.x+ / Splunk Cloud (Victoria + Classic), Python 3.x.

**Install** — drop the tarball into `$SPLUNK_HOME/etc/apps/`, untar, restart Splunk:

```sh
tar xzf SA-Data-Heartbeat-1.2.3.tar.gz -C $SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/bin/splunk restart
```

Then open `https://<your-splunk>/app/SA-Data-Heartbeat/monitor` and click **Enable Monitoring** to turn on the three scheduled searches.

## License

Each app ships with its own license file. See the `LICENSE.txt` inside each app's directory.

## Issues / contact

Bug reports and feature requests: open an issue in this repo.
Sales / commercial licensing: support@datadaytech.com
