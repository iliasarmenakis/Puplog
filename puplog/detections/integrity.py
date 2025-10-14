# detections/integrity.py
import re
import yaml
from datetime import datetime

SYSLOG_TS_FMT = "%b %d %H:%M:%S"

def _parse_ts(ts_str, year=None):
    if not ts_str:
        return None
    year = year or datetime.utcnow().year
    try:
        return datetime.strptime(f"{ts_str} {year}", f"{SYSLOG_TS_FMT} %Y")
    except Exception:
        return None

def detect_log_gaps(logs):
    """
    Identify large time gaps between consecutive log lines (in seconds) above threshold.
    """
    try:
        cfg = yaml.safe_load(open("config/rules.yml")) or {}
        gap = int(cfg.get("log_gap_seconds", 3600))
    except Exception:
        gap = 3600

    # extract timestamps in order
    ts_list = []
    for log in logs:
        t = _parse_ts(log.get("timestamp"))
        if t:
            ts_list.append(t)

    findings = []
    if len(ts_list) < 2:
        return findings

    ts_list.sort()
    for i in range(1, len(ts_list)):
        delta = (ts_list[i] - ts_list[i - 1]).total_seconds()
        if delta > gap:
            findings.append({
                "gap_seconds": int(delta),
                "prev": ts_list[i - 1].isoformat(),
                "next": ts_list[i].isoformat(),
                "indicator": "log_gap"
            })
    return findings

def detect_repeated_errors(logs):
    """
    Count repeated error messages per process and flag if above threshold within logs.
    """
    try:
        cfg = yaml.safe_load(open("config/rules.yml")) or {}
        threshold = int(cfg.get("repeated_error_threshold", 10))
    except Exception:
        threshold = 10

    counter = {}
    for log in logs:
        msg = log.get("message", "")
        proc = log.get("process", "unknown")
        if "error" in msg.lower() or "failed" in msg.lower():
            key = (proc, msg.strip()[:120])  # coarse message grouping
            counter[key] = counter.get(key, 0) + 1

    findings = []
    for (proc, text), count in counter.items():
        if count >= threshold:
            findings.append({"process": proc, "message": text, "count": count})
    return findings

def detect_config_changes(logs):
    """
    Look for edits to critical config filenames like sshd_config, iptables, etc.
    """
    try:
        cfg = yaml.safe_load(open("config/rules.yml")) or {}
        files = cfg.get("config_files", ["sshd_config", "iptables", "fstab", "/etc/ssh/sshd_config"])
    except Exception:
        files = ["sshd_config", "iptables", "fstab", "/etc/ssh/sshd_config"]

    findings = []
    for log in logs:
        msg = log.get("message", "")
        for f in files:
            if f in msg:
                if "modified" in msg.lower() or "changed" in msg.lower() or "edit" in msg.lower() or "update" in msg.lower():
                    findings.append({
                        "timestamp": log.get("timestamp"),
                        "host": log.get("host"),
                        "process": log.get("process"),
                        "message": msg,
                        "indicator": f"cfg_edit:{f}"
                    })
    return findings
