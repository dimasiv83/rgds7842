#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import math
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple
from urllib import request, error
from email.utils import parsedate_to_datetime

USER_AGENT = "DomainExpirationChecker/1.0 (+https://example.invalid)"
DEFAULT_FILE = "domains.txt"

# Reasonable defaults for alerting thresholds (days)
DEFAULT_WARN_DAYS = 30
DEFAULT_CRIT_DAYS = 7


def debug(msg: str) -> None:
    if os.environ.get("DOMAIN_CHECKER_DEBUG"):
        print(f"[debug] {msg}", file=sys.stderr)


def to_ascii_domain(domain: str) -> str:
    d = domain.strip().lower()
    # strip inline comments following '#'
    if "#" in d:
        d = d.split("#", 1)[0].strip()
    if not d:
        return ""
    try:
        # encode using IDNA (punycode) for IDN support
        return d.encode("idna").decode("ascii")
    except Exception:
        return d


def is_plausible_domain(domain: str) -> bool:
    if not domain or "." not in domain:
        return False
    if len(domain) > 253:
        return False
    # very permissive; allows xn-- labels
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    pattern = re.compile(rf"^(?:{label}\.)+{label}$")
    return bool(pattern.match(domain))


def parse_domains_file(path: str) -> List[str]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Domains file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    # supports comma and/or newlines as separators
    raw_items = re.split(r"[\n,]", content)
    domains: List[str] = []
    seen = set()
    for item in raw_items:
        d = to_ascii_domain(item)
        if not d:
            continue
        if not is_plausible_domain(d):
            debug(f"Skipping invalid domain syntax: {d}")
            continue
        if d not in seen:
            seen.add(d)
            domains.append(d)
    return domains


class RdapClient:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.ssl_ctx = ssl.create_default_context()

    def http_get_json(self, url: str) -> Optional[Dict]:
        req = request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"})
        try:
            with request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx) as resp:
                data = resp.read()
                if not data:
                    return None
                return json.loads(data.decode("utf-8", errors="replace"))
        except error.HTTPError as e:
            debug(f"HTTPError {e.code} for {url}")
            return None
        except error.URLError as e:
            debug(f"URLError {e.reason} for {url}")
            return None
        except Exception as e:
            debug(f"HTTP exception for {url}: {e}")
            return None

    def get_expiration(self, domain: str) -> Tuple[Optional[dt.datetime], Optional[str]]:
        # Try community aggregator first
        agg_url = f"https://rdap.org/domain/{domain}"
        data = self.http_get_json(agg_url)
        if data:
            exp = self._extract_expiration_from_rdap(data)
            if exp:
                return exp, "rdap.org"
        # Try IANA bootstrap to find registry RDAP server
        bootstrap = self.http_get_json("https://data.iana.org/rdap/dns.json")
        if bootstrap and "services" in bootstrap:
            tld = domain.rsplit(".", 1)[-1]
            services = bootstrap.get("services", [])
            for service in services:
                domains_list, urls_list = service
                if any(tld == s.lstrip(".") for s in domains_list):
                    for base in urls_list:
                        base = base.rstrip("/")
                        rdap_url = f"{base}/domain/{domain}"
                        data = self.http_get_json(rdap_url)
                        if data:
                            exp = self._extract_expiration_from_rdap(data)
                            if exp:
                                return exp, base
        return None, None

    @staticmethod
    def _extract_expiration_from_rdap(obj: Dict) -> Optional[dt.datetime]:
        events = obj.get("events") or []
        for ev in events:
            action = (ev.get("eventAction") or "").lower()
            if action in {"expiration", "expiry", "expires"}:
                date_str = ev.get("eventDate")
                if date_str:
                    parsed = parse_datetime_any(date_str)
                    if parsed:
                        return parsed
        # Some RDAPs include "notAfter" in status or remarks; try generic search
        text = json.dumps(obj)
        m = re.search(r"(?i)expir\w+\D{0,10}(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}[ T]\d{0,2}:?\d{0,2}:?\d{0,2}Z?)", text)
        if m:
            parsed = parse_datetime_any(m.group(1))
            if parsed:
                return parsed
        return None


def run_whois(domain: str, timeout: float = 10.0) -> Optional[str]:
    try:
        p = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=timeout)
        out = p.stdout or ""
        if not out.strip():
            return None
        return out
    except FileNotFoundError:
        debug("whois command not found")
        return None
    except subprocess.TimeoutExpired:
        debug("whois command timed out")
        return None
    except Exception as e:
        debug(f"whois exception: {e}")
        return None


def whois_query_socket(server: str, query: str, timeout: float = 10.0) -> Optional[str]:
    try:
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
            sock.shutdown(socket.SHUT_WR)
            chunks: List[bytes] = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        return text if text.strip() else None
    except Exception as e:
        debug(f"whois socket error {server}: {e}")
        return None


def get_iana_whois_server_for_tld(tld: str, timeout: float = 5.0) -> Optional[str]:
    # Query whois.iana.org with TLD to get authoritative whois server
    try:
        resp = whois_query_socket("whois.iana.org", tld, timeout=timeout)
        if not resp:
            return None
        for line in resp.splitlines():
            line_stripped = line.strip()
            m = re.match(r"^(?:refer|whois):\s*(\S+)$", line_stripped, flags=re.IGNORECASE)
            if m:
                server = m.group(1).strip()
                # don't return iana itself for domain queries
                if server.lower() == "whois.iana.org":
                    continue
                return server
    except Exception as e:
        debug(f"iana whois lookup failed for {tld}: {e}")
    return None


WHOIS_TLD_FALLBACK: Dict[str, str] = {
    # Common gTLDs
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.nic.biz",
    "xyz": "whois.nic.xyz",
    # ccTLDs and popular sTLDs
    "io": "whois.nic.io",
    "me": "whois.nic.me",
    "ru": "whois.tcinet.ru",
    "su": "whois.tcinet.ru",
    "xn--p1ai": "whois.tcinet.ru",  # .рф
    "uz": "whois.cctld.uz",
    # Google TLDs
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
}


def run_whois_socket(domain: str, timeout: float = 10.0) -> Optional[Tuple[str, str]]:
    # Returns (server, response) or None
    tld = domain.rsplit(".", 1)[-1].lower()
    srv = get_iana_whois_server_for_tld(tld, timeout=min(timeout, 5.0))
    if not srv:
        srv = WHOIS_TLD_FALLBACK.get(tld)
    if not srv:
        return None
    debug(f"query whois server {srv} for {domain}")
    txt = whois_query_socket(srv, domain, timeout=timeout)
    if not txt and srv.endswith("verisign-grs.com"):
        # verisign supports an exact match '=' prefix; try it if empty
        txt = whois_query_socket(srv, "=" + domain, timeout=timeout)
    if txt:
        return srv, txt
    return None


REFERRAL_PATTERNS = [
    r"Registrar WHOIS Server:\s*(\S+)",
    r"Whois Server:\s*(\S+)",
    r"ReferralServer:\s*whois://(\S+)",
]


def extract_referral_server(text: str) -> Optional[str]:
    for pat in REFERRAL_PATTERNS:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            host = m.group(1).strip()
            # strip scheme if present
            host = re.sub(r"^whois://", "", host)
            # some include port e.g., host:43
            host = host.split("/", 1)[0]
            host = host.split(":", 1)[0]
            if host and "." in host:
                return host
    return None

WHOIS_EXPIRATION_PATTERNS = [
    r"Registry Expiry Date:\s*(.+)",
    r"Registrar Registration Expiration Date:\s*(.+)",
    r"Expiration Date:\s*(.+)",
    r"Expiry Date:\s*(.+)",
    r"Expires On:\s*(.+)",
    r"Domain Expires:\s*(.+)",
    r"exp-date:\s*(.+)",
    r"paid-till:\s*(.+)",
    r"free-date:\s*(.+)",
    r"renewal date:\s*(.+)",
    r"expire:\s*(.+)",
    r"expires:\s*(.+)",
    r"validity:\s*(.+)",
    r"Expiration Time:\s*(.+)",
    r"Domain Expiration Date:\s*(.+)",
]


def extract_expiration_from_whois(text: str) -> Optional[dt.datetime]:
    # Drop comments
    cleaned_lines: List[str] = []
    for line in text.splitlines():
        if line.strip().startswith("%") or line.strip().startswith("#"):
            continue
        cleaned_lines.append(line)
    cleaned = "\n".join(cleaned_lines)

    for pat in WHOIS_EXPIRATION_PATTERNS:
        m = re.search(pat, cleaned, flags=re.IGNORECASE)
        if m:
            raw = m.group(1).strip()
            # kill trailing timezone names in parenthesis
            raw = re.sub(r"\s*\([^)]*\)$", "", raw)
            parsed = parse_datetime_any(raw)
            if parsed:
                return parsed
    # Generic fallback: look for any line with 'expir'
    for line in cleaned.splitlines():
        if "expir" in line.lower():
            # extract date-ish substring
            m = re.search(r"(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?:[ T]\d{1,2}:\d{2}:\d{2})?)", line)
            if m:
                parsed = parse_datetime_any(m.group(1))
                if parsed:
                    return parsed
    return None


KNOWN_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%Y.%m.%d %H:%M:%S",
    "%Y.%m.%d",
    "%d.%m.%Y %H:%M:%S",
    "%d.%m.%Y",
    "%Y/%m/%d",
    "%d-%b-%Y",
    "%d-%b-%Y %H:%M:%S %Z",
    "%b %d %Y",
    "%a %b %d %H:%M:%S %Z %Y",
]


def parse_datetime_any(value: str) -> Optional[dt.datetime]:
    v = value.strip()
    for fmt in KNOWN_FORMATS:
        try:
            d = dt.datetime.strptime(v, fmt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=dt.timezone.utc)
            return d.astimezone(dt.timezone.utc)
        except Exception:
            continue
    # Try RFC2822-like parsing
    try:
        d2 = parsedate_to_datetime(v)
        if d2 is not None:
            if d2.tzinfo is None:
                d2 = d2.replace(tzinfo=dt.timezone.utc)
            return d2.astimezone(dt.timezone.utc)
    except Exception:
        pass
    # Try to sniff numeric-only date
    m = re.search(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", v)
    if m:
        try:
            d3 = dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=dt.timezone.utc)
            return d3
        except Exception:
            pass
    return None


def classify(expiry: Optional[dt.datetime], warn_days: int, crit_days: int) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    if expiry is None:
        return "UNKNOWN"
    if expiry <= now:
        return "CRITICAL"
    days_left = (expiry - now).total_seconds() / 86400.0
    if days_left <= crit_days:
        return "CRITICAL"
    if days_left <= warn_days:
        return "WARNING"
    return "OK"


def days_left(expiry: Optional[dt.datetime]) -> Optional[int]:
    if expiry is None:
        return None
    now = dt.datetime.now(dt.timezone.utc)
    delta_days = (expiry - now).total_seconds() / 86400.0
    # Round down to be conservative
    return math.floor(delta_days)


def format_dt(d: Optional[dt.datetime]) -> str:
    if d is None:
        return "—"
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def check_domain(domain: str, rdap_client: RdapClient, timeout: float) -> Dict:
    exp: Optional[dt.datetime] = None
    source: Optional[str] = None

    exp, source = rdap_client.get_expiration(domain)
    if exp is None:
        # try system whois
        w = run_whois(domain, timeout=timeout)
        if w:
            exp = extract_expiration_from_whois(w)
            if exp is not None:
                source = "whois"
            else:
                # follow referral if present
                ref = extract_referral_server(w)
                if ref:
                    wr = whois_query_socket(ref, domain, timeout=timeout)
                    if not wr and ref.endswith("verisign-grs.com"):
                        wr = whois_query_socket(ref, "=" + domain, timeout=timeout)
                    if wr:
                        exp_r = extract_expiration_from_whois(wr)
                        if exp_r is not None:
                            exp = exp_r
                            source = f"whois({ref})"
        # try socket whois by tld server
        if exp is None:
            ws = run_whois_socket(domain, timeout=timeout)
            if ws:
                srv, txt = ws
                exp_s = extract_expiration_from_whois(txt)
                if exp_s is not None:
                    exp = exp_s
                    source = f"whois({srv})"

    return {"domain": domain, "expiration": exp, "source": source}


def exit_code_for(statuses: List[str]) -> int:
    if any(s == "CRITICAL" for s in statuses):
        return 2
    if any(s == "WARNING" for s in statuses):
        return 1
    if any(s == "UNKNOWN" for s in statuses):
        return 3
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Check domain expiration dates (RDAP first, WHOIS fallback)")
    parser.add_argument("--file", "-f", default=DEFAULT_FILE, help="Path to domains list (default: domains.txt)")
    parser.add_argument("--warn-days", type=int, default=DEFAULT_WARN_DAYS, help="Warning threshold in days (default: 30)")
    parser.add_argument("--crit-days", type=int, default=DEFAULT_CRIT_DAYS, help="Critical threshold in days (default: 7)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout seconds (default: 10)")
    parser.add_argument("--json", action="store_true", help="Print results as JSON")

    args = parser.parse_args(argv)

    try:
        domains = parse_domains_file(args.file)
    except Exception as e:
        print(f"Ошибка: не удалось прочитать файл с доменами: {e}", file=sys.stderr)
        return 4

    if not domains:
        print("Предупреждение: список доменов пуст.")
        return 0

    rdap_client = RdapClient(timeout=args.timeout)

    results = []
    for d in domains:
        res = check_domain(d, rdap_client, timeout=args.timeout)
        results.append(res)

    # Build statuses
    output_rows = []
    statuses = []
    for res in results:
        exp = res["expiration"]
        status = classify(exp, args.warn_days, args.crit_days)
        statuses.append(status)
        row = {
            "domain": res["domain"],
            "expiration": format_dt(exp),
            "days_left": days_left(exp),
            "status": status,
            "source": res.get("source"),
        }
        output_rows.append(row)

    if args.json:
        print(json.dumps(output_rows, ensure_ascii=False, indent=2))
    else:
        # Human-readable Russian output
        print("Домен; Дата окончания (UTC); Осталось (дней); Статус; Источник")
        for row in output_rows:
            dl = row["days_left"]
            dl_str = "—" if dl is None else str(dl)
            src = row.get("source") or "—"
            print(f"{row['domain']}; {row['expiration']}; {dl_str}; {row['status']}; {src}")

    return exit_code_for(statuses)


if __name__ == "__main__":
    sys.exit(main())
