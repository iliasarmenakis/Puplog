import re
import yaml
from collections import Counter

def detect_bruteforce(logs):
    try:
        with open("config/rules.yml", "r") as f:
            rules = yaml.safe_load(f).get("bruteforce", {})
    except Exception as e:
        print(f"[!] Could not load brute force rules: {e}")
        return []

    pattern = rules.get("pattern", "Failed password for")
    threshold = rules.get("threshold", 5)

    failed_ips = []
    for log in logs:
        msg = log.get("message", "")
        if re.search(pattern, msg):
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", msg)
            if ip_match:
                failed_ips.append(ip_match.group(1))

    ip_counts = Counter(failed_ips)
    suspicious = [{"ip": ip, "failures": count} for ip, count in ip_counts.items() if count >= threshold]
    return suspicious
