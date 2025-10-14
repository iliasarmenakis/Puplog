import requests

def send_discord_alert(webhook_url, detections):
    """
    Sends a short summary of detections to a Discord webhook.
    Handles different detection types safely.
    """
    if not webhook_url:
        return

    if not detections:
        return

    lines = []
    for d in detections[:10]:  # limit to 10 detections for brevity
        det_type = d.get("detection", "unknown")
        ip = d.get("ip", "N/A")
        msg = d.get("message", "")
        extra = ""

        # Customize message based on detection type
        if det_type == "bruteforce":
            extra = f"({d.get('failures', '?')} failed logins)"
        elif det_type == "port_scan":
            extra = f"({d.get('unique_ports', '?')} unique ports)"
        elif det_type == "privilege_escalation":
            extra = f"({d.get('process', '')})"

        # Trim message for readability
        short_msg = (msg[:80] + "...") if len(msg) > 80 else msg
        lines.append(f"- **{det_type}** | `{ip}` {extra}\n> {short_msg}")

    content = "🐶 **Puplog Alert Summary**\n\n" + "\n".join(lines)

    try:
        response = requests.post(webhook_url, json={"content": content})
        if response.status_code in (200, 204):
            print("[+] Sent alert to Discord.")
        else:
            print(f"[!] Discord responded with {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[!] Failed to send Discord alert: {e}")
