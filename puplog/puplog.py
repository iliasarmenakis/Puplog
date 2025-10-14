import yaml
import sys
from parsers.linux_parser import parse_syslog

# detections
from detections.brute_force import detect_bruteforce
from detections.privilege_escalation import detect_privilege_escalation
from detections.port_scan import detect_port_scan

# exporters
from exporters.json_exporter import export_json
from exporters.csv_exporter import export_csv

# alerts
try:
    from alerts.discord_alert import send_discord_alert
except ImportError:
    send_discord_alert = None

# enrichment
from alerts.enrich import enrich_detections

# new detections
from detections.network import (
    detect_suspicious_login_times,
    detect_failed_logins_subnet,
    detect_external_access_violations,
    detect_unusual_port_usage
)
from detections.system import (
    detect_suspicious_process_execution,
    detect_unexpected_privilege_escalation,
    detect_new_user_accounts,
    detect_unusual_file_modification
)
from detections.integrity import (
    detect_log_gaps,
    detect_repeated_errors,
    detect_config_changes
)
from detections.malware import (
    detect_known_bad_filenames,
    detect_unexpected_outbound_connections,
    detect_command_injection_patterns
)

MENU = """
🐶 Puplog — choose detection to run:
1) Brute-force detection
2) Privilege escalation detection
3) Port-scan detection
4) Network anomalies (login times, failed subnets, external access, unusual ports)
5) System anomalies (suspicious process, unexpected priv escalation, new user, file mods)
6) Log integrity & config changes (log gaps, repeated errors, config edits)
7) Malware / suspicious activity (bad filenames, outbound connections, command injection)
8) Run all detections
9) Exit
Enter choice [1-9]: """

def load_settings():
    try:
        with open("config/settings.yml", "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print("[!] Missing config/settings.yml")
        sys.exit(1)

def run_and_collect(logs, choice):
    results = {}

    if choice in ("1", "8"):
        results["bruteforce"] = detect_bruteforce(logs)
    if choice in ("2", "8"):
        results["privilege_escalation"] = detect_privilege_escalation(logs)
    if choice in ("3", "8"):
        results["port_scan"] = detect_port_scan(logs)

    if choice in ("4", "8"):  # network anomalies
        results["network_login_times"] = detect_suspicious_login_times(logs)
        results["failed_logins_subnet"] = detect_failed_logins_subnet(logs)
        results["external_access"] = detect_external_access_violations(logs)
        results["unusual_ports"] = detect_unusual_port_usage(logs)

    if choice in ("5", "8"):  # system anomalies
        results["suspicious_process"] = detect_suspicious_process_execution(logs)
        results["unexpected_priv"] = detect_unexpected_privilege_escalation(logs)
        results["new_user_accounts"] = detect_new_user_accounts(logs)
        results["file_modifications"] = detect_unusual_file_modification(logs)

    if choice in ("6", "8"):  # log integrity & config
        results["log_gaps"] = detect_log_gaps(logs)
        results["repeated_errors"] = detect_repeated_errors(logs)
        results["config_changes"] = detect_config_changes(logs)

    if choice in ("7", "8"):  # malware / suspicious activity
        results["bad_filenames"] = detect_known_bad_filenames(logs)
        results["outbound_connections"] = detect_unexpected_outbound_connections(logs)
        results["command_injection"] = detect_command_injection_patterns(logs)

    return results

def flatten_results(results):
    """
    Convert dict of detection lists into a single flat list for exporting/alerting,
    while tagging each with its detection type.
    """
    flat = []
    for det_type, items in results.items():
        for it in items:
            row = {"detection": det_type}
            # merge the item fields, but detection field stays
            row.update(it)
            flat.append(row)
    return flat


def pretty_print(results):
    """
    Print all detections in a structured way.
    Shows up to 30 findings per detector type.
    """
    for det, items in results.items():
        print(f"\n[+] {det} -> {len(items)} finding(s)")
        for it in items[:30]:
            # Brute-force
            if det == "bruteforce":
                print(f"  - {it.get('ip')} ({it.get('failures')} failures)")

            # Privilege escalation
            elif det == "privilege_escalation":
                print(f"  - {it.get('timestamp')} {it.get('host')} : {it.get('message')}")

            # Port scan
            elif det == "port_scan":
                print(f"  - {it.get('ip')} (unique_ports={it.get('unique_ports')})")

            # Network anomalies
            elif det == "network_login_times":
                print(f"  - {it.get('timestamp')} {it.get('host')} : {it.get('indicator')}")
            elif det == "failed_logins_subnet":
                print(f"  - Subnet {it.get('subnet')} -> {it.get('failures')} failed logins")
            elif det == "external_access":
                print(f"  - {it.get('timestamp')} {it.get('host')} : external login from {it.get('ip')}")
            elif det == "unusual_ports":
                print(f"  - {it.get('ip')} connected to unusual ports: {it.get('ports')}")

            # System anomalies
            elif det == "suspicious_process":
                print(f"  - {it.get('timestamp')} {it.get('host')} : {it.get('indicator')} -> {it.get('message')}")
            elif det == "unexpected_priv":
                print(f"  - {it.get('timestamp')} {it.get('host')} : {it.get('indicator')} -> {it.get('message')}")
            elif det == "new_user_accounts":
                print(f"  - {it.get('timestamp')} {it.get('host')} : new user -> {it.get('message')}")
            elif det == "file_modifications":
                print(f"  - {it.get('timestamp')} {it.get('host')} : modified {it.get('indicator')}")

            # Log integrity & config
            elif det == "log_gaps":
                print(f"  - Gap {it.get('gap_seconds')}s between {it.get('prev')} and {it.get('next')}")
            elif det == "repeated_errors":
                print(f"  - {it.get('process')} : '{it.get('message')}' repeated {it.get('count')} times")
            elif det == "config_changes":
                print(f"  - {it.get('timestamp')} {it.get('host')} : config edited -> {it.get('indicator')}")

            # Malware / suspicious activity
            elif det == "bad_filenames":
                print(f"  - {it.get('timestamp')} {it.get('host')} : bad filename -> {it.get('indicator')}")
            elif det == "outbound_connections":
                print(f"  - {it.get('timestamp')} {it.get('host')} : {it.get('process')} -> outbound {it.get('ip')}")
            elif det == "command_injection":
                print(f"  - {it.get('timestamp')} {it.get('host')} : potential injection -> {it.get('indicator')}")

            # Fallback for unknown detectors
            else:
                print(f"  - {it}")

        if len(items) > 30:
            print(f"    ... ({len(items) - 30} more)")


def main():
    print("🐶 Puplog – Lightweight Log Analysis & Detection Tool\n")
    settings = load_settings()
    log_path = settings.get("log_path")
    webhook = settings.get("discord_webhook", "")
    json_out = settings.get("export_json", "detections.json")
    csv_out = settings.get("export_csv", "detections.csv")

    print(f"[+] Reading logs from: {log_path}")
    logs = parse_syslog(log_path)
    if not logs:
        print("[!] No logs parsed. Exiting.")
        return

    while True:
        choice = input(MENU).strip()
        if choice == "9":
            print("Bye.")
            break
        if choice not in {"1","2","3","4","5","6","7","8"}:
            print("[!] Invalid choice.")
            continue

        results = run_and_collect(logs, choice)
        pretty_print(results)

        flat = flatten_results(results)
        if flat:
            print("[+] Enriching detections with context...")
            try:
                enriched = enrich_detections(flat, logs, sample_size=3, do_geo=False, do_rdns=False)
            except Exception as e:
                print(f"[!] Enrichment failed: {e}")
                enriched = flat

            export_json(enriched, json_out)
            export_csv(enriched, csv_out)

            # send optional alert
            if webhook and send_discord_alert:
                send_discord_alert(webhook, enriched)
            elif webhook and not send_discord_alert:
                print("[!] Alert module not available (discord_alert not found).")
        else:
            print("[+] No detections to export or alert.")

        # If user chose single detection, break after run — optional. We keep loop to allow multiple runs.
        cont = input("\nRun another detection? (y/N): ").strip().lower()
        if cont != "y":
            print("Exiting.")
            break

if __name__ == "__main__":
    main()
