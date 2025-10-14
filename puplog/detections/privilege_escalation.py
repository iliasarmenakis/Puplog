import re
import yaml

def detect_privilege_escalation(logs):
    """
    Detects potential privilege escalation events using simple pattern matches.
    Returns list of matches with context (timestamp, host, process, message).
    """
    try:
        with open("config/rules.yml", "r") as f:
            rules = yaml.safe_load(f).get("privilege_escalation", {})
    except Exception as e:
        print(f"[!] Could not load privilege escalation rules: {e}")
        return []

    # rules may contain a list of patterns
    patterns = rules.get("patterns", ["sudo:", "session opened for user root", "uid=0"])
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

    findings = []
    for log in logs:
        msg = log.get("message", "")
        for pat in compiled:
            if pat.search(msg):
                findings.append({
                    "timestamp": log.get("timestamp"),
                    "host": log.get("host"),
                    "process": log.get("process"),
                    "message": msg,
                    "indicator": pat.pattern
                })
                break
    return findings
