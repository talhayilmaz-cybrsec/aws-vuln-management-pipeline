"""Threat-intelligence enrichment: CISA KEV catalog and FIRST EPSS scores.

Both are free, public feeds. Results are cached in memory for the lifetime
of the Lambda execution environment, so a burst of findings costs one KEV
download, not hundreds. Every failure degrades gracefully: a feed outage
must never stop findings from being recorded.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.parse
import urllib.request
from typing import Callable

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_TTL_SECONDS = 6 * 3600
USER_AGENT = "aws-vuln-management-pipeline/1.0 (+https://github.com/talhayilmaz-cybrsec/aws-vuln-management-pipeline)"

Fetcher = Callable[[str], dict]


def http_get_json(url: str, timeout: float = 10.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URLs only
        return json.load(resp)


class ThreatIntel:
    def __init__(self, fetch: Fetcher = http_get_json, clock: Callable[[], float] = time.time):
        self._fetch = fetch
        self._clock = clock
        self._kev: set[str] | None = None
        self._kev_loaded_at = 0.0
        self._epss_cache: dict[str, float | None] = {}

    # --- CISA KEV ------------------------------------------------------------

    def _kev_ids(self) -> set[str] | None:
        if self._kev is not None and self._clock() - self._kev_loaded_at < KEV_TTL_SECONDS:
            return self._kev
        try:
            data = self._fetch(KEV_URL)
            self._kev = {v["cveID"].upper() for v in data.get("vulnerabilities", []) if "cveID" in v}
            self._kev_loaded_at = self._clock()
            log.info("Loaded CISA KEV catalog: %d CVEs", len(self._kev))
        except Exception:  # feed outage: keep the last good copy if we have one
            log.exception("Could not load CISA KEV catalog")
        return self._kev

    def in_kev(self, cve: str | None) -> bool:
        if not cve:
            return False
        ids = self._kev_ids()
        return bool(ids) and cve.upper() in ids

    def kev_available(self) -> bool:
        return self._kev_ids() is not None

    # --- FIRST EPSS ----------------------------------------------------------

    def epss(self, cve: str | None) -> float | None:
        if not cve or not cve.upper().startswith("CVE-"):
            return None
        cve = cve.upper()
        if cve not in self._epss_cache:
            try:
                data = self._fetch(f"{EPSS_URL}?{urllib.parse.urlencode({'cve': cve})}")
                rows = data.get("data") or []
                self._epss_cache[cve] = float(rows[0]["epss"]) if rows else None
            except Exception:
                log.exception("EPSS lookup failed for %s", cve)
                return None  # not cached: retry on the next finding
        return self._epss_cache[cve]
