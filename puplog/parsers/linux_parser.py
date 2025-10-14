import re

def parse_syslog(path):
    """Parses a basic Linux syslog into structured dicts."""
    logs = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                match = re.match(
                    r"(\w+\s+\d+\s[\d:]+)\s+(\S+)\s+(\S+):\s+(.*)", line
                )
                if match:
                    logs.append({
                        "timestamp": match.group(1),
                        "host": match.group(2),
                        "process": match.group(3),
                        "message": match.group(4),
                    })
    except FileNotFoundError:
        print(f"[!] Log file not found: {path}")
    except Exception as e:
        print(f"[!] Error reading log file: {e}")

    return logs
