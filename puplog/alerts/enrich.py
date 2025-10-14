import socket
import time
from datetime import datetime
from collections import defaultdict
from functools import lru_cache

# optional imports
try:
    import geoip2.database  
except Exception:
    geoip2 = None

try:
    import requests
except Exception:
    requests = None

# Parser timestamp format 
SYSLOG_TS_FMT = "%b %d %H:%M:%S"


def _parse_ts(ts_str, year=None):
    """
    Parse syslog-like timestamp string to a datetime.
    If year is None, assume current year.
    """
    if ts_str is None:
        return None
    year = year or datetime.utcnow().year
    try:
        dt = datetime.strptime(f"{ts_str} {year}", f"{SYSLOG_TS_FMT} %Y")
        return dt
    except Exception:
        return None

def _match_logs_for_ip(logs, ip):
    """
    Return list of logs whose message contains the ip (string match).
    Use direct string match to avoid heavy regex for every call.
    """
    matched = []
    for log in logs:
        msg = log.get("message", "") if isinstance(log, dict) else str(log)
        if ip in msg:
            matched.append(log)
    return matched

class GeoIPEnricher:
    """
    Try to use MaxMind local DB first (geoip2), otherwise use ip-api.com as fallback.
    Simple, synchronous, with caching.
    """

    def __init__(self, mmdb_path=None, timeout=3, use_web_fallback=True):
        self.mmdb_path = mmdb_path
        self.use_web = use_web_fallback and (requests is not None)
        self.timeout = timeout
        self._reader = None
        if geoip2 and mmdb_path:
            try:
                self._reader = geoip2.database.Reader(mmdb_path)
            except Exception:
                self._reader = None

    @lru_cache(maxsize=4096)
    def lookup(self, ip):
        """
        Return dict: {country, region, city, lat, lon, isp, org} or {} on failure.
        """
        if self._reader:
            try:
                rec = self._reader.city(ip)
                return {
                    "country": rec.country.name,
                    "region": rec.subdivisions.most_specific.name,
                    "city": rec.city.name,
                    "latitude": rec.location.latitude,
                    "longitude": rec.location.longitude,
                    "source": "maxmind-local"
                }
            except Exception:
                pass

        if self.use_web:
            try:
                url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,message"
                r = requests.get(url, timeout=self.timeout)
                if r.status_code == 200:
                    j = r.json()
                    if j.get("status") == "success":
                        return {
                            "country": j.get("country"),
                            "region": j.get("regionName"),
                            "city": j.get("city"),
                            "latitude": j.get("lat"),
                            "longitude": j.get("lon"),
                            "isp": j.get("isp"),
                            "org": j.get("org"),
                            "source": "ip-api.com"
                        }
            except Exception:
                pass
        return {}

@lru_cache(maxsize=4096)
def reverse_dns(ip, timeout=3):
    """
    Try to resolve PTR (reverse DNS). Returns hostname or empty string.
    Uses socket.gethostbyaddr; wrapped in try/except to avoid raising.
    """
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""

def enrich_detections(detections, logs, geoip_enricher=None, sample_size=3, year=None, do_geo=True, do_rdns=True):
    """
    Enrich a list of detection dicts in-place (or shallow-copied) and return them.
    detections: list of dicts (must include either 'ip' or some identifier)
    logs: parsed logs (list of dicts with 'timestamp' and 'message')
    geoip_enricher: optional GeoIPEnricher instance. If None, a default one is created (web fallback enabled if requests available).
    sample_size: how many example log lines to attach.
    year: year to assume when parsing syslog timestamps.
    do_geo, do_rdns: toggles for network lookups.
    """
    if geoip_enricher is None:
        geoip_enricher = GeoIPEnricher(mmdb_path=None, use_web_fallback=True)

    enriched = []
    for d in detections:
        det = dict(d) 
        ip = det.get("ip") or det.get("src_ip") or det.get("source_ip")

        # default placeholders
        det.setdefault("first_seen", None)
        det.setdefault("last_seen", None)
        det.setdefault("sample_lines", [])
        det.setdefault("geo", {})
        det.setdefault("rdns", "")

        if ip:
            matched = _match_logs_for_ip(logs, ip)
            ts_list = []
            samples = []
            for m in matched:
                ts = _parse_ts(m.get("timestamp"), year=year)
                if ts:
                    ts_list.append(ts)
                if len(samples) < sample_size:
                    tstr = m.get("timestamp", "")
                    samples.append(f"{tstr} {m.get('message','')}")
            if ts_list:
                first = min(ts_list).isoformat()
                last = max(ts_list).isoformat()
                det["first_seen"] = first
                det["last_seen"] = last
            det["sample_lines"] = samples

            
            if do_geo and ip:
                try:
                    geo = geoip_enricher.lookup(ip)
                    if geo:
                        det["geo"] = geo
                except Exception:
                    det["geo"] = det.get("geo", {})

            # Reverse DNS (optional)
            if do_rdns and ip:
                try:
                    det["rdns"] = reverse_dns(ip)
                except Exception:
                    det["rdns"] = ""

        else:
            # For detections without an IP 
            fragment = det.get("message") or det.get("process") or det.get("indicator")
            if fragment:
                samples = []
                for m in logs:
                    if fragment in m.get("message", ""):
                        if len(samples) < sample_size:
                            samples.append(f"{m.get('timestamp','')} {m.get('message','')}")
                if samples:
                    det["sample_lines"] = samples
                    ts_list = [_parse_ts(m.split(" ",3)[0]) for m in samples if m]
                    ts_list = [t for t in ts_list if t]
                    if ts_list:
                        det["first_seen"] = min(ts_list).isoformat()
                        det["last_seen"] = max(ts_list).isoformat()

        enriched.append(det)

    return enriched

