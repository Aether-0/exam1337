"""Detect credential exposure in plaintext HTTP requests (authorized captures only)."""
import json
import re
from urllib.parse import parse_qs, urlsplit

SENSITIVE = {"password", "passwd", "pass", "pwd", "secret", "api_key", "apikey", "token", "access_token", "refresh_token", "client_secret"}
DEMO = "POST /login HTTP/1.1\r\nHost: lab.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=student&password=example"

def _sensitive(key):
    key = key.lower().strip().replace("-", "_")
    return key in SENSITIVE or key.endswith(("_password", "_secret", "_token"))

def _json_fields(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if _sensitive(str(key)):
                yield str(key)
            yield from _json_fields(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _json_fields(value)

def analyze_http(raw):
    """Return findings with no credential values."""
    head, sep, body = raw.partition("\r\n\r\n")
    if not sep:
        head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        return []
    match = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/1\.[01]$", lines[0])
    if not match:
        return []
    method, target = match.groups()
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    findings = []
    def flag(issue, location):
        item = {"issue": issue, "location": location, "method": method, "endpoint": urlsplit(target).path or "/"}
        if item not in findings:
            findings.append(item)
    auth = headers.get("authorization", "").lower()
    if auth.startswith(("basic ", "bearer ")):
        flag("Authentication credentials sent over plaintext HTTP", "Authorization header")
    for cookie in headers.get("cookie", "").split(";"):
        if "=" in cookie and _sensitive(cookie.split("=", 1)[0]):
            flag("Sensitive cookie sent over plaintext HTTP", "Cookie header")
    for key in parse_qs(urlsplit(target).query, keep_blank_values=True):
        if _sensitive(key):
            flag("Credential in plaintext HTTP query", "query field: " + key)
    content_type = headers.get("content-type", "").lower()
    if "application/x-www-form-urlencoded" in content_type:
        for key in parse_qs(body, keep_blank_values=True):
            if _sensitive(key):
                flag("Credential in plaintext HTTP body", "form field: " + key)
    elif "application/json" in content_type:
        try:
            for key in _json_fields(json.loads(body)):
                flag("Credential in plaintext HTTP body", "JSON field: " + key)
        except (ValueError, TypeError):
            pass
    return findings

def scan(raw=None):
    """Scan an HTTP request, or a synthetic demo when omitted."""
    findings = analyze_http(DEMO if raw is None else raw)
    for item in findings:
        print("[WARNING]", item["issue"], "("+item["location"]+")")
    print("[exam1337] Scan completed:", len(findings), "finding(s).")
    return findings

def scan_pcap(path):
    """Inspect HTTP/1.x payloads in a saved capture. Requires scapy.

    Does not reassemble TCP streams; fragmented requests may be missed.
    """
    try:
        from scapy.all import rdpcap, TCP, Raw
    except ImportError as exc:
        raise RuntimeError("Install scapy: pip install scapy") from exc
    findings = []
    for packet in rdpcap(path):
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = bytes(packet[Raw].load).decode("latin-1", errors="replace")
            findings.extend(analyze_http(payload))
    return findings
