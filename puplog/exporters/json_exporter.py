import json

def export_json(data, filename):
    """
    Exports `data` (list/dict) to a JSON file.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"[+] Exported detections to {filename}")
    except Exception as e:
        print(f"[!] Failed to export JSON: {e}")
