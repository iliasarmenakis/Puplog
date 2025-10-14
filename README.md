# Puplog
Puplog – Lightweight Log Analysis &amp; Detection Tool
Puplog — Custom Log Analysis & Alerting Tool 🐶
Overview

Puplog is a lightweight, modular log analysis and alerting tool designed for cybersecurity investigations and threat detection. It parses system and application logs, detects suspicious patterns, enriches alerts with context, and exports results for automation or reporting.

Puplog is perfect for incident response automation, security tooling demos, and portfolio showcases.

!**Features**!

**Log Parsing**

-Linux syslog (/var/log/syslog), Windows Event Logs (planned), Apache logs.

-Modular parser architecture for future log types.

**Detection Capabilities**
Puplog currently includes multiple detection modules:

Detection Types
-> Brute-force attacks	          | Multiple failed logins from the same IP

-> Privilege escalation           | sudo abuse, unexpected su sessions, suspicious processes

-> Port scanning	                | Rapid connection attempts to multiple ports

-> Network anomalies	            | Suspicious login times, failed logins per subnet, external access violations, unusual port usage

-> System anomalies	              | New user accounts, suspicious file modifications, unexpected privilege escalations

-> Log integrity & config         | Log gaps, repeated errors, configuration changes

-> Malware / suspicious activity	| Known bad filenames, unexpected outbound connections, command injection patterns


**Enrichment & Alerts**

-- Adds context: sample log lines, first/last timestamps, host info.

-- Optional geo IP lookup and reverse DNS enrichment.

-- Alerting via Discord, with JSON and CSV export support.


Exporting
- JSON and CSV export for integration with SIEMs, dashboards, or custom scripts.
- 
- Discord Webhook reporting availability
- 

**Usage**
Puplog provides an interactive CLI:

🐶 Puplog — choose detection to run:
1) Brute-force detection
2) Privilege escalation detection
3) Port-scan detection
4) Network anomalies
5) System anomalies
6) Log integrity & config changes
7) Malware / suspicious activity
8) Run all detections
9) Exit
Enter choice [1-9]:


**Contribution**

Puplog is modular and designed to easily add new parsers and detection modules. Contributions are welcome:
1 Add new detectors to detections/.
2 Add new parsers to parsers/.
3 Ensure pretty_print() and flatten_results() support new fields.
4 Submit a pull request with tests and sample logs.

**Future Work / Roadmap**

- Windows Event Log parsing
- SIEM integration (Elastic, Splunk)
- Dockerized one-command demo environment
- Continuous monitoring via systemd or container orchestrator
- Additional alert channels (Slack, Teams, email)

**Changing Log Source and Discord Webhook**

Puplog is configurable via the config/settings.yml file. You can adjust the log file path and Discord webhook URL without modifying the code.

1️⃣ Open the configuration file

File path: config/settings.yml
Open it in any text editor (Notepad, VS Code, nano, etc.).

2️⃣ Update the log file path

log_path: /path/to/your/logfile.log

3️⃣ Update the Discord webhook (optional)

discord_webhook: "https://discord.com/api/webhooks/XXXXXXXX/XXXXXXXX"

4️⃣ Save the file

After saving, run Puplog as usual:

5️⃣ Notes

Changes take effect the next time you run Puplog.
JSON/CSV exports will still use the file paths defined in settings.yml (can also be updated there).
