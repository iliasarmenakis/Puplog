# detections/system.py
import re
import yaml

def detect_suspicious_process_execution(logs):
    """
    Flag process executions or commands coming from /tmp or other writable dirs.
    Looks for 'COMMAND=' or obvious '/tmp/' paths in messages.
    """
    try:
        cfg = yaml.safe_load(open("config/rules.yml")) or {}
        suspect_paths = cfg.get("suspicious_exec_paths", ["/tmp/", "/var/tmp/"])
    except Exception:
        suspect_paths = ["/tmp/", "/var/tmp/"]

    findings = []
    for log in logs:
        msg = log.get("message", "")
        for p in suspect_paths:
            if p in msg and ("COMMAND=" in msg or "exec" in msg.lower() or ".sh" in msg.lower()):
                findings.append({
                    "timestamp": log.get("timestamp"),
                    "host": log.get("host"),
                    "process": log.get("process"),
                    "message": msg,
                    "indicator": f"exec_from_{p}"
                })
                break
    return findings

def detect_unexpected_privilege_escalation(logs):
    """
    Beyond sudo: watch for suspicious 'uid=0' by non-root or strange su/sudo patterns.
    """
    try:
        cfg = yaml.safe_load(open("config/rules.yml")) or {}
        patterns = cfg.get("unexpected_priv_patterns", ["uid=0", "setuid", "setgid"])
    except Exception:
        patterns = ["uid=0", "setuid", "setgid"]

    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

    findings = []
    for log in logs:
        msg = log.get("message", "")
        for c in compiled:
            if c.search(msg):
                findings.append({
                    "timestamp": log.get("timestamp"),
                    "host": log.get("host"),
                    "process": log.get("process"),
                    "message": msg,
                    "indicator": c.pattern
                })
                break
    return findings

def detect_new_user_accounts(logs):
    """
    Look for 'useradd', 'adduser', or 'new user' messages in logs.
    """
    findings = []
    for log in logs:
        msg = log.get("message", "")
        if "useradd" in msg or "adduser" in msg or "new user" in msg.lower():
            findings.append({
                "timestamp": log.get("timestamp"),
                "host": log.get("host"),
                "process": log.get("process"),
                "message": msg,
                "indicator": "user_creation"
            })
    return findings

def detect_unusual_file_modification(logs):
    """
    Flag writes or modifications to sensitive paths (/etc, /var/log) when not expected.
    """
    try:
        cfg = yaml.safe_load(open("config/rules.yml")) or {}
        sensitive_paths = cfg.get("sensitive_paths", ["/etc", "/var/log", "/usr/bin"])
    except Exception:
        sensitive_paths = ["/etc", "/var/log", "/usr/bin"]

    findings = []
    for log in logs:
        msg = log.get("message", "")
        lower = msg.lower()
        if ("modified" in lower or "wrote" in lower or "changed" in lower or "chmod" in lower):
            for p in sensitive_paths:
                if p in msg:
                    findings.append({
                        "timestamp": log.get("timestamp"),
                        "host": log.get("host"),
                        "process": log.get("process"),
                        "message": msg,
                        "indicator": f"mod_{p}"
                    })
                    break
    return findings
