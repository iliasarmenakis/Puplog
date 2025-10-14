# detections/network.py
import re
import yaml
from collections import Counter, defaultdict
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

def _ip_to_subnet(ip, mask=24):
    # simple /24 subnet extraction for IPv4
    parts = ip.split('.')
    if len(parts) != 4:
        return ip
    return '.'.join(parts[:3]) + '.0/24' if mask == 24 else '.'.join(parts)

def _extract_ip(msg):
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", msg)
    return m.group(1) if m else None

def detect_suspicious_login_times(logs):
    """
    Flag successful login events at 'odd' hours defined in config.
    Looks for 'Accepted password' or 'Accepted publickey' messages.
    """
    try:
        cfg = yaml.safe_load(open("config/rules.yml")) or {}
        hours = cfg.get("suspicious_login_hours", {"start": 0, "end": 5})
    except Exception:
        hours = {"start": 0, "end": 5}

    start = int(hours.get("start", 0))
    end = int(hours.get("end", 5))

    findings = []
    for log in logs:
        msg = log.get("message", "")
        if "Accepted password" in msg or "Accepted publickey" in msg:
            ts = _parse_ts(log.get("timestamp"))
            if ts:
                h = ts.hour
                if start <= h <= end:
                    findings.append({
                        "timestamp": log.get("timestamp"),
                        "host": log.get("host"),
                        "process": log.get("process"),
                        "message": msg,
                        "indicator": f"login_at_{h}h"
                    })
    return findings

def detect_failed_logins_subnet(logs):
    """
    Count failed login attempts grouped by /24 subnet and flag subnets above threshold.
    """
    try:
        cfg = yaml.safe_load(open("config/rules.yml")) or {}
        threshold = int(cfg.get("failed_subnet_threshold", 20))
    except Exception:
        threshold = 20

    subnet_counts = Counter()
    for log in logs:
        msg = log.get("message", "")
        if "Failed password" in msg or "authentication failure" in msg.lower():
            ip = _extract_ip(msg)
            if ip:
                sn = _ip_to_subnet(ip)
                subnet_counts[sn] += 1

    findings = []
    for sn, count in subnet_counts.items():
        if count >= threshold:
            findings.append({"subnet": sn, "failures": count})
    return findings

def detect_external_access_violations(logs):
    """
    Flag Accepted logins from external (non-RFC1918) IPs.
    """
    def _is_private(ip):
        return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.20.") or ip.startswith("172.21.") or ip.startswith("172.22.") or ip.startswith("172.23.") or ip.startswith("172.24.") or ip.startswith("172.25.") or ip.startswith("172.26.") or ip.startswith("172.27.") or ip.startswith("172.28.") or ip.startswith("172.29.") or ip.startswith("172.30.") or ip.startswith("172.31.")

    findings = []
    for log in logs:
        msg = log.get("message", "")
        if "Accepted password" in msg or "Accepted publickey" in msg:
            ip = _extract_ip(msg)
            if ip and not _is_private(ip):
                findings.append({
                    "timestamp": log.get("timestamp"),
                    "host": log.get("host"),
                    "process": log.get("process"),
                    "ip": ip,
                    "message": msg,
                    "indicator": "external_login"
                })
    return findings

def detect_unusual_port_usage(logs):
    """
    Look for connection lines with destination ports and flag if port not in allowed list from config.
    """
    try:
        cfg = yaml.safe_load(open("config/rules.yml")) or {}
        allowed = set(cfg.get("allowed_ports", [22,80,443,53,3306]))
        threshold = int(cfg.get("unusual_port_threshold", 1))  # one hit is suspicious
    except Exception:
        allowed = {22,80,443,53,3306}
        threshold = 1

    ip_ports = defaultdict(set)
    findings = []

    for log in logs:
        msg = log.get("message", "")
        # capture DPT=<n> or 'port <n>'
        p_match = re.findall(r"(?:DPT=|dpt=|port\s+)(\d{1,5})", msg)
        ip = _extract_ip(msg)
        if p_match and ip:
            for p in p_match:
                try:
                    port = int(p)
                except ValueError:
                    continue
                if port not in allowed:
                    ip_ports[ip].add(port)

    for ip, ports in ip_ports.items():
        if len(ports) >= threshold:
            findings.append({"ip": ip, "ports": sorted(list(ports)), "unique_ports": len(ports)})

    return findings
