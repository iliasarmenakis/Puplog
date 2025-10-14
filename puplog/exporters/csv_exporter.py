import csv

def export_csv(data, filename):
    """
    Exports list-of-dicts data to CSV.
    Dynamically collects all keys across all items so no fieldnames mismatch.
    """
    if not data:
        open(filename, "w", encoding="utf-8").close()
        print(f"[+] Exported empty CSV to {filename}")
        return

    # Collect all unique keys from all dicts
    headers = sorted({key for item in data for key in item.keys()})

    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            for row in data:
                writer.writerow(row)
        print(f"[+] Exported detections to {filename}")
    except Exception as e:
        print(f"[!] Failed to export CSV: {e}")
