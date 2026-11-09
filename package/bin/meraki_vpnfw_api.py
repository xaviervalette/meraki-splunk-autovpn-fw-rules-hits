"""Minimal read-only Meraki Dashboard API client (stdlib only)."""

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "TA-meraki-vpnfw/1.0.0 SplunkAddOn"
MAX_RETRIES = 5
_NEXT_LINK = re.compile(r'<([^>]+)>;\s*rel=next')


class MerakiClient:
    def __init__(self, api_key, base_url="https://api.meraki.com/api/v1", timeout=30, logger=None):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.logger = logger

    def _request(self, url):
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        })
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8") or "null"), resp.headers.get("Link", "")
            except urllib.error.HTTPError as e:
                if e.code != 429 and e.code < 500 or attempt == MAX_RETRIES:
                    raise
                wait = int(e.headers.get("Retry-After", 2 ** attempt))
                if self.logger:
                    self.logger.warning("Meraki API %s on %s, retry %d in %ss", e.code, url, attempt, wait)
                time.sleep(wait)

    def get(self, path, params=None):
        url = f"{self.base_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        return self._request(url)[0]

    def get_all(self, path, params=None):
        """Follow Link rel=next pagination."""
        url = f"{self.base_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        items = []
        while url:
            page, link = self._request(url)
            items.extend(page or [])
            match = _NEXT_LINK.search(link or "")
            url = match.group(1) if match else None
        return items

    def organization(self, org_id):
        return self.get(f"/organizations/{org_id}")

    def vpn_firewall_rules(self, org_id):
        return (self.get(f"/organizations/{org_id}/appliance/vpn/vpnFirewallRules") or {}).get("rules", [])

    def appliances(self, org_id):
        return self.get_all(f"/organizations/{org_id}/devices",
                            {"productTypes[]": ["appliance"], "perPage": 1000})
