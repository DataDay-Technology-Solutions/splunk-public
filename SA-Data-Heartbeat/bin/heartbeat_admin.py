#!/usr/bin/env python3
"""
SA-Data-Heartbeat custom REST handler.

Splunk's splunkweb /__raw/ proxy intermittently drops POST writes for some
saved searches (the "disabled=0 returned 200 but didn't persist" bug we
verified end-to-end). This handler runs INSIDE splunkd via the persist
script mechanism, talking to localhost:8089 directly — which is reliable.

Endpoint:  /services/data_heartbeat/admin
Methods:   POST action=enable_all   →  enables all 3 monitoring searches
           POST action=disable_all  →  disables all 3
           POST action=test_alert   →  fires the dispatcher with a synthetic
                                       result row for the named alert action
"""
import json
import logging
import os
import sys

# Splunk bundles splunklib with the platform; persist scripts get a session
# key + a Splunkd connection without us needing pip-installed deps.
import splunk.persistconn.application as application
import splunk.rest as rest

APP_NAME = "SA-Data-Heartbeat"

# Splunk built-in capabilities that gate the destructive endpoints. The
# handler refuses requests from users that don't hold at least one of these.
#
# `edit_search_scheduler` is the right least-privilege match for toggling
# scheduled-search state (Splunk's own UI requires it). `admin_all_objects`
# is the standard catch-all that the `admin` and `sc_admin` roles hold.
# Without this gate, any authenticated user (incl. the default `user` role)
# could call our admin endpoint to enable/disable monitoring or trigger
# arbitrary outbound HTTP POSTs via the test-alert path — i.e. SSRF +
# control-plane tampering by a low-priv account.
_REQUIRED_CAPABILITIES = ("edit_search_scheduler", "admin_all_objects")
SEARCH_NAMES = [
    "Data Heartbeat - Source Type Monitor",
    "Data Heartbeat Alert - Flagged Sources",
    "Data Heartbeat - Auto Discovery",
]

LOG_PATH = os.path.join(
    os.environ.get("SPLUNK_HOME", "/opt/splunk"),
    "var", "log", "splunk", "heartbeat_admin.log",
)
logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
                    format="%(asctime)s level=%(levelname)s %(message)s")
log = logging.getLogger("heartbeat_admin")


def _current_user_capabilities(session_key):
    """Return the capability set of the authenticated user (by session key).
    Returns an empty set if the lookup fails — we fail closed."""
    try:
        resp, content = rest.simpleRequest(
            "/services/authentication/current-context",
            sessionKey=session_key,
            getargs={"output_mode": "json"},
            method="GET",
            raiseAllErrors=False,
        )
        if int(getattr(resp, "status", 0) or 0) != 200:
            return set()
        if isinstance(content, (bytes, bytearray)):
            content = content.decode("utf-8", "ignore")
        data = json.loads(content)
        caps = (data.get("entry") or [{}])[0].get("content", {}).get("capabilities") or []
        return set(caps)
    except (json.JSONDecodeError, ValueError, TypeError, OSError) as e:
        log.warning("capability lookup failed: %s", e)
        return set()


def _post_search_state(session_key, name, enabled):
    """POST disabled + is_scheduled to a saved-search entity via splunkd local REST."""
    path = "/servicesNS/nobody/{app}/saved/searches/{name}".format(
        app=APP_NAME, name=name,
    )
    body = {
        "disabled": "0" if enabled else "1",
        "is_scheduled": "1" if enabled else "0",
    }
    # rest.simpleRequest goes through splunkd directly (port 8089), not splunkweb.
    # This is the reliable path that bypasses the proxy filter on disabled-field POSTs.
    # Returns (Response-like-object, content); we read .status off the response.
    resp, _content = rest.simpleRequest(path, sessionKey=session_key, method="POST",
                                        postargs=body, raiseAllErrors=False)
    status = int(getattr(resp, "status", 0) or 0)
    return 200 <= status < 300, status


def _do_enable_all(session_key, enabled):
    results = {}
    all_ok = True
    for name in SEARCH_NAMES:
        ok, status = _post_search_state(session_key, name, enabled)
        results[name] = {"ok": ok, "http": status}
        if not ok:
            all_ok = False
            log.warning("enable_all[%s]: http=%s", name, status)
    return all_ok, results


def _do_test_alert(session_key, action_type, target_config):
    """Invoke the dispatcher's slack/teams/webhook path with a synthetic row.
    We don't go through the saved-search → action.heartbeat_dispatch chain
    because we want immediate feedback; instead we shell out to the dispatcher
    script directly with a minimal payload."""
    import subprocess
    import tempfile
    import gzip
    import csv
    import shutil
    # Write a one-row results CSV that the dispatcher can read. Use a
    # try/finally so the tmp dir is always cleaned up — each test-alert
    # click previously leaked a directory on disk.
    tmpdir = tempfile.mkdtemp(prefix="hb_test_")
    try:
        csv_path = os.path.join(tmpdir, "results.csv")
        with open(csv_path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["sourcetype", "threshold_minutes", "minutes_since_seen",
                        "status", "importance", "alert_action", "alert_action_config"])
            w.writerow(["heartbeat:test", "60", "0", "test", "high",
                        action_type, target_config])
        gz_path = csv_path + ".gz"
        with open(csv_path, "rb") as src, gzip.open(gz_path, "wb") as dst:
            dst.writelines(src)
        payload = json.dumps({
            "search_name": "Data Heartbeat - Test Alert",
            "trigger_time_rendered": "now",
            "results_link": "",
            "session_key": session_key,
            "results_file": gz_path,
        })
        splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
        cmd = [
            os.path.join(splunk_home, "bin", "splunk"), "cmd", "python3",
            os.path.join(splunk_home, "etc", "apps", APP_NAME, "bin", "heartbeat_dispatch.py"),
            "--execute",
        ]
        try:
            p = subprocess.run(cmd, input=payload.encode("utf-8"),
                               capture_output=True, timeout=15)
            return p.returncode == 0, {"stdout": p.stdout.decode("utf-8", "ignore")[:500],
                                        "stderr": p.stderr.decode("utf-8", "ignore")[:500]}
        except subprocess.TimeoutExpired:
            return False, {"error": "timeout"}
        except OSError as e:
            return False, {"error": str(e)}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


class HeartbeatAdminHandler(application.PersistentServerConnectionApplication):
    """Splunk persist REST handler. Reachable at /services/data_heartbeat/admin."""

    def __init__(self, command_line, command_arg):
        pass

    def handle(self, in_string):
        # in_string is bytes on Splunk 10.x persist handlers; json.loads handles both.
        try:
            req = json.loads(in_string) if isinstance(in_string, (str, bytes, bytearray)) else in_string
        except (json.JSONDecodeError, ValueError):
            return self._reply(400, {"error": "bad_json"})
        if not isinstance(req, dict):
            return self._reply(400, {"error": "bad_request_shape"})

        log.info("handle: top-level keys = %s", list(req.keys()))

        session_key = (req.get("session") or {}).get("authtoken") or req.get("session_key", "")
        if not session_key:
            return self._reply(401, {"error": "no_session"})

        # Splunk persist handler shapes the request differently between versions.
        # Accept any of: form list-of-{name,value} dicts, form dict, query list,
        # or top-level "payload" (JSON body) for clients that POST application/json.
        post = {}
        form = req.get("form")
        if isinstance(form, list):
            for kv in form:
                if isinstance(kv, dict) and "name" in kv:
                    post[kv["name"]] = kv.get("value", "")
                elif isinstance(kv, (list, tuple)) and len(kv) == 2:
                    post[kv[0]] = kv[1]
        elif isinstance(form, dict):
            post = dict(form)
        # also accept query-string params
        query = req.get("query")
        if isinstance(query, list):
            for kv in query:
                if isinstance(kv, dict) and "name" in kv:
                    post.setdefault(kv["name"], kv.get("value", ""))
                elif isinstance(kv, (list, tuple)) and len(kv) == 2:
                    post.setdefault(kv[0], kv[1])
        # also accept raw JSON body
        raw_payload = req.get("payload")
        if isinstance(raw_payload, str) and raw_payload:
            try:
                body_obj = json.loads(raw_payload)
                if isinstance(body_obj, dict):
                    for k, v in body_obj.items():
                        post.setdefault(k, v)
            except (json.JSONDecodeError, ValueError):
                pass

        log.info("handle: parsed post=%s", {k: ("***" if k == "target" else v) for k, v in post.items()})
        action = post.get("action", "")

        # Capability gate. Every action this handler exposes is privileged:
        #   - enable_all / disable_all flip scheduled-search state (control plane)
        #   - test_alert triggers arbitrary outbound HTTP via the dispatcher
        # Requiring at least one of {edit_search_scheduler, admin_all_objects}
        # matches Splunk's own RBAC for these operations and prevents low-priv
        # roles (e.g. default `user`) from tampering or SSRF-probing internal
        # hosts through the dispatcher.
        if action in ("enable_all", "disable_all", "test_alert"):
            caps = _current_user_capabilities(session_key)
            if not caps.intersection(_REQUIRED_CAPABILITIES):
                log.warning(
                    "denied action=%s — caller lacks %s (has %d caps)",
                    action, "/".join(_REQUIRED_CAPABILITIES), len(caps),
                )
                return self._reply(403, {
                    "error": "insufficient_capability",
                    "required_any_of": list(_REQUIRED_CAPABILITIES),
                })

        if action == "enable_all":
            ok, results = _do_enable_all(session_key, True)
            return self._reply(200 if ok else 207, {"ok": ok, "results": results})

        if action == "disable_all":
            ok, results = _do_enable_all(session_key, False)
            return self._reply(200 if ok else 207, {"ok": ok, "results": results})

        if action == "test_alert":
            action_type = post.get("action_type", "")
            target_config = post.get("target", "")
            if not action_type or not target_config:
                return self._reply(400, {"error": "missing action_type or target"})
            ok, detail = _do_test_alert(session_key, action_type, target_config)
            return self._reply(200 if ok else 500, {"ok": ok, "detail": detail})

        return self._reply(400, {"error": "unknown action"})

    @staticmethod
    def _reply(status, body):
        return {"status": status, "payload": json.dumps(body)}
