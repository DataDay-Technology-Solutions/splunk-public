#!/usr/bin/env python3
"""
SA-Data-Heartbeat custom alert action.

Splunk invokes this script after the "Data Heartbeat Alert - Flagged Sources"
search runs and produces results. Each result row is one flagged sourcetype.

For each row we look up its (alert_action, alert_action_config) from the per-row
lookup `heartbeat_alert_actions.csv` and dispatch:
  - email  → use Splunk's configured SMTP via `| sendemail` SPL
  - slack  → POST JSON to the configured incoming-webhook URL
  - teams  → POST JSON to the configured incoming-webhook URL
  - webhook→ POST a generic JSON payload
  - none / unset → skip (default)

All HTTP/SMTP failures are logged to $SPLUNK_HOME/var/log/splunk/heartbeat_dispatch.log
so an operator can grep for delivery failures without re-running the alert.

Splunk passes us the alert payload as JSON on stdin. Format documented at:
https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModAlertsLog
"""
import csv
import gzip
import json
import logging
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Per-action concurrency caps. Slack incoming webhooks rate-limit at roughly
# 1 req/sec sustained per app/channel; we use 2 workers + 429-backoff to stay
# under that. Teams is more permissive. Generic webhook gets a higher cap.
_CONCURRENCY = {
    "slack":   2,
    "teams":   4,
    "webhook": 8,
    "email":   4,  # SMTP is server-side; only limits us via Splunk's | sendemail
}
_DEFAULT_CONCURRENCY = 4

# Pre-action throttle: minimum gap between two consecutive dispatches of the
# same action type per-process. Slack defaults to 1.1s; webhook to 0.05s.
_MIN_GAP_SEC = {
    "slack":   1.1,
    "teams":   0.3,
    "webhook": 0.05,
    "email":   0.2,
}
_last_dispatch_time = {}    # action_type → epoch of last dispatch
_throttle_lock = Lock()


def _throttle(action_type: str):
    """Enforce a minimum gap between successive dispatches of the same action.

    Computes the wake time *inside* the lock then releases it before sleeping
    so other workers in the pool can serialize on the *schedule* without
    queueing on the lock during the sleep itself.
    """
    gap = _MIN_GAP_SEC.get(action_type, 0.0)
    if gap <= 0:
        return
    with _throttle_lock:
        last = _last_dispatch_time.get(action_type, 0.0)
        now = time.monotonic()
        my_slot = max(now, last + gap)
        _last_dispatch_time[action_type] = my_slot
        wait = my_slot - now
    if wait > 0:
        time.sleep(wait)


# Two SSL contexts:
#   _SSL_CTX           — strict verification, used for all *external* webhook
#                        traffic (Slack/Teams/PagerDuty/generic). Splunkbase
#                        reviewers flag insecure defaults; users can opt out
#                        for self-signed corporate webhooks with
#                        HEARTBEAT_DISPATCH_INSECURE=1.
#   _LOCAL_SPLUNKD_CTX — relaxed verification, ONLY used for talking back to
#                        splunkd at the URI Splunk gave us (server_uri/
#                        SPLUNKD_URI — typically https://127.0.0.1:8089).
#                        splunkd ships with a self-signed cert by default;
#                        the session key is what actually authenticates us.
#                        Keeping this scoped means external traffic stays
#                        strict.
def _build_ssl_context():
    insecure = os.environ.get("HEARTBEAT_DISPATCH_INSECURE", "0") == "1"
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _build_local_splunkd_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


_SSL_CTX = _build_ssl_context()
_LOCAL_SPLUNKD_CTX = _build_local_splunkd_ctx()


_SAFE_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _is_local_splunkd(uri: str) -> bool:
    try:
        host = urllib.parse.urlparse(uri).hostname or ""
    except (ValueError, AttributeError):
        return False
    return host.lower() in _SAFE_LOCAL_HOSTS


def _validate_webhook_url(url: str) -> bool:
    """Ensure a target string is a real http(s) URL before handing it to
    urlopen. Catches user errors like '#channel' (Slack channel name) or
    'recipient@example.com' (mistakenly typed in a webhook field)."""
    if not url or not isinstance(url, str):
        return False
    try:
        p = urllib.parse.urlparse(url)
    except (ValueError, AttributeError):
        return False
    return p.scheme in ("http", "https") and bool(p.netloc)


# Conservative RFC-ish email match. The character class explicitly excludes
# every character that has SPL meaning in a double-quoted string (quote,
# backslash, pipe, dollar, backtick, parens/brackets/braces) so a recipient
# value cannot break out of `to="..."` into the surrounding pipeline.
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
)


def _validate_email_recipients(value: str) -> list:
    """Split a recipients string on comma/semicolon and return the valid
    addresses. Anything that doesn't strictly match the email pattern —
    including quotes, pipes, backslashes, parens, dollar signs, backticks,
    and control chars — is rejected before we interpolate into the
    `| sendemail` SPL string."""
    if not value or not isinstance(value, str):
        return []
    parts = [p.strip() for p in value.replace(";", ",").split(",")]
    return [p for p in parts if p and _EMAIL_RE.match(p)]


def _sanitize_spl_value(value) -> str:
    """Strip characters that could break out of an SPL double-quoted string.
    Used for sourcetype/importance values interpolated into the email body."""
    s = "" if value is None else str(value)
    # Drop control chars, quotes, backslashes, and pipes — none of these
    # are legitimate in a sourcetype name or any other field we use here.
    return "".join(c for c in s if c >= " " and c not in '"\\|`$')

LOG_FILENAME = os.path.join(
    os.environ.get("SPLUNK_HOME", "/opt/splunk"), "var", "log", "splunk", "heartbeat_dispatch.log"
)
logging.basicConfig(
    filename=LOG_FILENAME,
    level=logging.INFO,
    format="%(asctime)s level=%(levelname)s %(message)s",
)
log = logging.getLogger("heartbeat_dispatch")

APP_NAME = "SA-Data-Heartbeat"
HTTP_TIMEOUT_S = 10


def _read_app_version() -> str:
    """Read the app version from default/app.conf so the User-Agent header
    always matches the shipped build (avoids stale version strings in code)."""
    try:
        path = os.path.join(
            os.environ.get("SPLUNK_HOME", "/opt/splunk"),
            "etc", "apps", APP_NAME, "default", "app.conf",
        )
        with open(path, "r", encoding="utf-8") as fh:
            in_launcher = False
            for line in fh:
                s = line.strip()
                if s.startswith("[") and s.endswith("]"):
                    in_launcher = (s == "[launcher]")
                    continue
                if in_launcher and s.startswith("version"):
                    parts = s.split("=", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
    except (OSError, ValueError):
        pass
    return "0.0.0"


_APP_VERSION = _read_app_version()
_USER_AGENT = f"{APP_NAME}/{_APP_VERSION}"

# Maps each supported action type to the JSON key inside its global
# `config_json` (in heartbeat_alert_actions.csv) that holds the "target" —
# i.e. the recipient list for email, the webhook URL for slack/teams/webhook.
# Used by load_global_defaults() to translate Settings-page config into a
# simple {action_type: default_target} map the dispatch loop can fall back to.
_GLOBAL_TARGET_KEY = {
    "email":   "recipients",
    "slack":   "webhook_url",
    "teams":   "webhook_url",
    "webhook": "url",
}


def load_global_defaults() -> dict:
    """Read heartbeat_alert_actions.csv and return {action_type: default_target}.
    Only includes actions that are both enabled=1 AND have a non-empty target
    field in config_json. If the file is missing or malformed, returns empty
    dict — per-row config still works (template fallback is optional)."""
    path = os.path.join(
        os.environ.get("SPLUNK_HOME", "/opt/splunk"),
        "etc", "apps", APP_NAME, "lookups", "heartbeat_alert_actions.csv",
    )
    defaults = {}
    if not os.path.exists(path):
        return defaults
    try:
        with open(path, "r", newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                action = (row.get("action_type") or "").strip().lower()
                enabled = (row.get("enabled") or "0").strip()
                if enabled not in ("1", "true", "True"):
                    continue
                cfg_raw = row.get("config_json") or "{}"
                try:
                    cfg = json.loads(cfg_raw) if isinstance(cfg_raw, str) else {}
                except (json.JSONDecodeError, ValueError):
                    cfg = {}
                key = _GLOBAL_TARGET_KEY.get(action)
                if not key:
                    continue
                target = (cfg.get(key) or "").strip()
                if target:
                    defaults[action] = target
    except (OSError, csv.Error) as e:
        log.warning("could not read global alert action defaults: %s", e)
    return defaults


def read_alert_results(results_file: str) -> list:
    """Splunk hands us a gzipped CSV at $results_file. One row per flagged sourcetype."""
    if not results_file or not os.path.exists(results_file):
        return []
    try:
        with gzip.open(results_file, "rt", newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    except (OSError, csv.Error) as e:
        log.error("failed to read alert results %s: %s", results_file, e)
        return []


def build_payload(row: dict, alert_meta: dict) -> dict:
    """Stable payload schema for webhook/slack/teams. Documented for Splunkbase."""
    return {
        "app": APP_NAME,
        "alert_search": alert_meta.get("search_name", "Data Heartbeat Alert - Flagged Sources"),
        "fired_at": alert_meta.get("fired_at", ""),
        "splunk_url": alert_meta.get("splunk_url", ""),
        "sourcetype": row.get("sourcetype", ""),
        "importance": row.get("importance", ""),
        "status": row.get("status", "flagged"),
        "threshold_minutes": _to_number(row.get("threshold_minutes")),
        "minutes_since_seen": _to_number(row.get("minutes_since_seen")),
    }


def _to_number(value):
    try:
        if value is None or value == "":
            return None
        f = float(value)
        return int(f) if f.is_integer() else f
    except (TypeError, ValueError):
        return None


def _post_json(url: str, payload: dict, max_retries: int = 3) -> bool:
    """POST with built-in 429 backoff. Reads Retry-After header (in seconds)
    and sleeps that long before retrying. Falls back to exponential backoff.
    Rejects non-http(s) URLs up front so a typo'd Slack channel name like
    '#general' doesn't blow up urllib's url parser mid-loop."""
    if not _validate_webhook_url(url):
        log.error("invalid webhook url (not http/https): %r", url)
        return False
    body = json.dumps(payload).encode("utf-8")
    backoff = 1.0
    for attempt in range(1, max_retries + 1):
        req = urllib.request.Request(
            url, data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": _USER_AGENT,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S, context=_SSL_CTX) as resp:
                if 200 <= resp.status < 300:
                    return True
                log.warning("POST %s returned %s (attempt %d/%d)", url, resp.status, attempt, max_retries)
                if resp.status == 429:
                    retry_after = resp.headers.get("Retry-After")
                    sleep_s = float(retry_after) if (retry_after and retry_after.isdigit()) else backoff
                    time.sleep(min(sleep_s, 30))
                    backoff *= 2
                    continue
                return False
        except urllib.error.HTTPError as he:
            if he.code == 429 and attempt < max_retries:
                retry_after = he.headers.get("Retry-After") if he.headers else None
                sleep_s = float(retry_after) if (retry_after and retry_after.isdigit()) else backoff
                log.warning("POST %s 429 retry-after=%s (attempt %d/%d)", url, sleep_s, attempt, max_retries)
                time.sleep(min(sleep_s, 30))
                backoff *= 2
                continue
            log.error("POST %s HTTPError %s: %s", url, he.code, he.reason)
            return False
        except (urllib.error.URLError, OSError) as e:
            log.error("POST %s failed (attempt %d/%d): %s", url, attempt, max_retries, e)
            if attempt < max_retries:
                time.sleep(backoff)
                backoff *= 2
                continue
            return False
    return False


def dispatch_slack(payload: dict, webhook_url: str) -> bool:
    """Slack incoming-webhooks accept either a plain message or rich blocks.
    Keep this minimal so it works in default workspace settings."""
    msg = (
        f":warning: *{payload['app']}*: `{payload['sourcetype']}` flagged "
        f"({payload['minutes_since_seen']} min since last event, "
        f"threshold {payload['threshold_minutes']} min, importance {payload['importance']})"
    )
    return _post_json(webhook_url, {"text": msg})


def dispatch_teams(payload: dict, webhook_url: str) -> bool:
    """Microsoft Teams incoming-webhook MessageCard."""
    card = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "DC4E41",
        "summary": f"{payload['sourcetype']} flagged",
        "title": f"Data Heartbeat: {payload['sourcetype']} flagged",
        "sections": [{
            "facts": [
                {"name": "Importance", "value": payload["importance"]},
                {"name": "Threshold (min)", "value": str(payload["threshold_minutes"])},
                {"name": "Minutes since last event", "value": str(payload["minutes_since_seen"])},
            ],
        }],
    }
    return _post_json(webhook_url, card)


def dispatch_webhook(payload: dict, webhook_url: str) -> bool:
    """Generic JSON webhook — the documented payload schema."""
    return _post_json(webhook_url, payload)


def dispatch_email(
    payload: dict,
    recipients: str,
    splunk_session_key: str,
    splunkd_uri: str = "",
    max_retries: int = 3,
) -> bool:
    """Use Splunk's REST `email` action via the search head's configured SMTP.

    We dispatch a tiny one-off `| sendemail` SPL using the session key Splunk
    provides on the alert payload — no SMTP credentials in this script.

    Hardening:
      - Recipients are validated as RFC-ish email addresses; anything that
        could break out of the SPL double-quoted string (quotes, pipes,
        backslashes, control chars) is rejected before interpolation.
      - Sourcetype/importance in the body are sanitized for the same reason.
      - The splunkd URI is preferred from the alert payload's `server_uri`
        field and falls back to the SPLUNKD_URI env var. SSL verification is
        disabled *only* for the localhost loopback case (splunkd's self-
        signed cert) — external traffic still uses the strict context.
      - Retries with exponential backoff on transient errors, mirroring
        _post_json so transient SMTP/REST blips don't lose alerts.
    """
    valid_recipients = _validate_email_recipients(recipients)
    if not valid_recipients:
        log.error("invalid email recipients (rejected): %r", recipients)
        return False
    to_field = ", ".join(valid_recipients)
    splunkd_uri = (splunkd_uri or os.environ.get("SPLUNKD_URI", "")).strip() \
        or "https://localhost:8089"
    ctx = _LOCAL_SPLUNKD_CTX if _is_local_splunkd(splunkd_uri) else _SSL_CTX

    st = _sanitize_spl_value(payload.get("sourcetype"))
    imp = _sanitize_spl_value(payload.get("importance"))
    thr = _sanitize_spl_value(payload.get("threshold_minutes"))
    msec = _sanitize_spl_value(payload.get("minutes_since_seen"))
    splunk_url = _sanitize_spl_value(payload.get("splunk_url"))
    body_text = (
        f"Sourcetype: {st}\n"
        f"Importance: {imp}\n"
        f"Threshold (min): {thr}\n"
        f"Minutes since last event: {msec}\n"
        f"Splunk: {splunk_url}"
    )
    spl = (
        f"| makeresults | eval msg=\"{body_text}\" "
        f"| sendemail to=\"{to_field}\" "
        f"subject=\"[Data Heartbeat] {st} flagged\" "
        "message_from_inline_field=msg"
    )
    data = urllib.parse.urlencode({
        "search": "search " + spl,
        "exec_mode": "blocking",
        "output_mode": "json",
    }).encode("utf-8")

    backoff = 1.0
    for attempt in range(1, max_retries + 1):
        req = urllib.request.Request(
            splunkd_uri.rstrip("/") + "/services/search/jobs",
            data=data,
            headers={
                "Authorization": f"Splunk {splunk_session_key}",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": _USER_AGENT,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S, context=ctx) as resp:
                if 200 <= resp.status < 300:
                    return True
                log.warning(
                    "email dispatch returned %s for %s (attempt %d/%d)",
                    resp.status, to_field, attempt, max_retries,
                )
                if resp.status >= 500 and attempt < max_retries:
                    time.sleep(backoff); backoff *= 2
                    continue
                return False
        except urllib.error.HTTPError as he:
            if he.code >= 500 and attempt < max_retries:
                log.warning(
                    "email dispatch HTTP %s for %s — retrying (attempt %d/%d)",
                    he.code, to_field, attempt, max_retries,
                )
                time.sleep(backoff); backoff *= 2
                continue
            log.error("email dispatch failed for %s: HTTP %s %s", to_field, he.code, he.reason)
            return False
        except (urllib.error.URLError, OSError) as e:
            if attempt < max_retries:
                log.warning(
                    "email dispatch transient error for %s (attempt %d/%d): %s",
                    to_field, attempt, max_retries, e,
                )
                time.sleep(backoff); backoff *= 2
                continue
            log.error("email dispatch failed for %s: %s", to_field, e)
            return False
    return False


def main() -> int:
    if "--execute" not in sys.argv:
        print("This script is invoked by Splunk as a custom alert action.", file=sys.stderr)
        return 1

    try:
        payload_in = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError) as e:
        log.error("failed to parse Splunk alert payload: %s", e)
        return 2

    alert_meta = {
        "search_name": payload_in.get("search_name", ""),
        "fired_at": payload_in.get("trigger_time_rendered", ""),
        "splunk_url": payload_in.get("results_link", ""),
    }
    session_key = payload_in.get("session_key", "")
    splunkd_uri = (
        payload_in.get("server_uri")
        or payload_in.get("splunk_uri")
        or os.environ.get("SPLUNKD_URI", "")
    )
    results_file = payload_in.get("results_file", "")
    rows = read_alert_results(results_file)

    log.info("dispatch invoked: %d result rows", len(rows))

    # Settings-page-as-templates: load per-action defaults from
    # heartbeat_alert_actions.csv. If a row has alert_action="email" but its
    # alert_action_config is empty, the dispatcher falls back to the global
    # email recipient list configured in Settings. Per-row config wins when set.
    global_defaults = load_global_defaults()
    log.info("loaded global defaults for actions: %s", list(global_defaults.keys()))

    # Build the full work list first: one (action, target, payload, st) per
    # (row × action). Multi-action support: alert_action is comma-separated,
    # alert_action_config is pipe-separated in the same order.
    work = []
    skipped = 0
    for row in rows:
        actions_raw = (row.get("alert_action") or "none").strip()
        configs_raw = (row.get("alert_action_config") or "").strip()
        actions = [a.strip().lower() for a in actions_raw.split(",") if a.strip()]
        configs = [c.strip() for c in configs_raw.split("|")]
        st_label = row.get("sourcetype", "?")
        payload = build_payload(row, alert_meta)
        for idx, action in enumerate(actions):
            row_target = configs[idx] if idx < len(configs) else ""
            # Fall back to global default if the per-row target is empty.
            target = row_target if row_target else global_defaults.get(action, "")
            if action == "none" or not target:
                skipped += 1
                continue
            if action not in ("slack", "teams", "webhook", "email"):
                log.warning("unknown action '%s' for sourcetype %s", action, st_label)
                skipped += 1
                continue
            using = "row" if row_target else "global-default"
            log.info("dispatch enqueued %s/%s via %s", st_label, action, using)
            work.append((action, target, payload, st_label, session_key))

    if not work:
        log.info("dispatch complete: sent=0 skipped=%d failed=0", skipped)
        return 0

    # Group work by action so each pool has its own concurrency cap.
    by_action: dict = {}
    for w in work:
        by_action.setdefault(w[0], []).append(w)

    sent = 0
    failed = 0

    def _do_one(item):
        action, target, payload, st_label, sess = item
        _throttle(action)
        if action == "slack":
            return dispatch_slack(payload, target)
        if action == "teams":
            return dispatch_teams(payload, target)
        if action == "webhook":
            return dispatch_webhook(payload, target)
        if action == "email":
            return dispatch_email(payload, target, sess, splunkd_uri=splunkd_uri)
        return False

    # Per-action thread pool. Pools run sequentially per action type but
    # each pool dispatches its own items in parallel up to its cap. Each
    # future is mapped back to its work item so a thrown exception names
    # the offending (sourcetype, action) pair in the log — not just the
    # error message.
    for action, items in by_action.items():
        cap = _CONCURRENCY.get(action, _DEFAULT_CONCURRENCY)
        with ThreadPoolExecutor(max_workers=min(cap, len(items))) as ex:
            futures = {ex.submit(_do_one, w): w for w in items}
            for f in as_completed(futures):
                item = futures[f]
                _action, _target, _payload, _st, _sess = item
                try:
                    if f.result():
                        sent += 1
                    else:
                        failed += 1
                except Exception as e:
                    log.error(
                        "dispatcher exception for %s/%s: %s",
                        _st, _action, e,
                    )
                    failed += 1

    log.info("dispatch complete: sent=%d skipped=%d failed=%d", sent, skipped, failed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
