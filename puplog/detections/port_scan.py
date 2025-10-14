# detections/port_scan.py
import re
import yaml
from collections import defaultdict

IP_SRC_PATTERNS = [
    re.compile(r"SRC=(\d{1,3}(?:\.\d{1,3}){3})"),     # kernel-style
    re.compile(r"src=(\d{1,3}(?:\.\d{1,3}){3})"),     # lowercase
    re.compile(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})"),  # "from 1.2.3.4"
    re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")          # fallback: any ip
]

PORT_PATTERNS = [
    re.compile(r"DPT=(\d{1,5})"),        # kernel-style DPT=80
    re.compile(r"dpt=(\d{1,5})"),        # lowercase
    re.compile(r"port\s+(\d{1,5})"),     # "port 22"
    re.compile(r":\s*(\d{2,5})\b"),      # e.g. ":8080" in some logs (fallback)
]

def _extract_src_ip(msg):
    for p in IP_SRC_PATTERNS:
        m = p.search(msg)
        if m:
            return m.group(1)
    return None

def _extract_ports(msg):
    ports = set()
    for p in PORT_PATTERNS:
        for m in p.findall(msg):
            try:
                ports.add(int(m))
            except ValueError:
                continue
    return ports

def detect_port_scan(logs):
    """
    Heuristic port-scan detection:
      - Extract source IP by checking for SRC=, src=, 'from <ip>', or fallback any IP.
      - Extract port numbers from DPT=, dpt=, 'port <n>', or common variants.
      - Count unique destination ports per source IP, compare to threshold.
    Returns list of dicts: {ip, unique_ports, ports_sample}
    """
    try:
        with open("config/rules.yml", "r") as f:
            rules = yaml.safe_load(f).get("port_scan", {})
    except Exception as e:
        print(f"[!] Could not load port scan rules: {e}")
        rules = {}

    threshold = int(rules.get("unique_ports_threshold", 10))

    ip_ports = defaultdict(set)
    ip_examples = defaultdict(list)

    for log in logs:
        msg = log.get("message", "") if isinstance(log, dict) else str(log)
        src = _extract_src_ip(msg)
        if not src:
            continue

        ports = _extract_ports(msg)
        if not ports:
            # no explicit port found in this line
            continue

        for p in ports:
            ip_ports[src].add(p)
            if len(ip_examples[src]) < 8:
                ip_examples[src].append(p)

    suspicious = []
    for ip, ports in ip_ports.items():
        if len(ports) >= threshold:
            suspicious.append({
                "ip": ip,
                "unique_ports": len(ports),
                "ports_sample": sorted(list(ip_examples[ip]))  # a small sample of ports seen
            })

    return suspicious
