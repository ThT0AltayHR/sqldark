"""HTTP engine: sends requests, applies tamper chain, times responses."""
import random
import re
import time
import requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
]


class Response:
    __slots__ = ("status", "text", "headers", "elapsed", "url")

    def __init__(self, status, text, headers, elapsed, url):
        self.status = status
        self.text = text or ""
        self.headers = headers or {}
        self.elapsed = elapsed
        self.url = url

    @property
    def length(self):
        return len(self.text)


class HttpClient:
    def __init__(self, logger, timeout=15, delay=0.0, retries=2,
                 proxy=None, headers=None, cookies=None, tampers=None,
                 random_agent=False, verify=False, random_delay=0.0,
                 csrf_url=None, csrf_field=None):
        self.log = logger
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.tampers = tampers or []
        self.random_agent = random_agent
        self.verify = verify
        self.random_delay = random_delay
        self.csrf_url = csrf_url
        self.csrf_field = csrf_field
        self.session = requests.Session()
        self.session.verify = verify
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.headers["Cookie"] = cookies
        self.session.headers.setdefault("Accept", "*/*")
        self.request_count = 0

    def _tamper(self, payload):
        for t in self.tampers:
            payload = t.tamper(payload)
        return payload

    def send(self, url, method="GET", data=None, raw_payload=None):
        """Send a request. raw_payload is the already-built injected value."""
        if self.random_agent:
            self.session.headers["User-Agent"] = random.choice(USER_AGENTS)
        elif "User-Agent" not in self.session.headers:
            self.session.headers["User-Agent"] = USER_AGENTS[0]

        last_exc = None
        for attempt in range(self.retries + 1):
            try:
                if self.delay:
                    time.sleep(self.delay)
                if self.random_delay:
                    time.sleep(random.uniform(0, self.random_delay))
                data = self._inject_csrf(data)
                start = time.time()
                r = self.session.request(
                    method, url, data=data, timeout=self.timeout,
                    allow_redirects=False,
                )
                elapsed = time.time() - start
                self.request_count += 1
                return Response(r.status_code, r.text, dict(r.headers), elapsed, url)
            except requests.exceptions.Timeout:
                # Timeouts matter for time-based detection; surface as slow response.
                elapsed = self.timeout
                self.request_count += 1
                return Response(0, "", {}, elapsed, url)
            except requests.RequestException as e:
                last_exc = e
                time.sleep(0.5)
        self.log.error(f"request failed: {last_exc}")
        return Response(-1, "", {}, 0.0, url)

    def _inject_csrf(self, data):
        """If a CSRF endpoint is configured, fetch a fresh token and fold it
        into the POST body under the configured field name (anti-CSRF bypass
        for authorized testing of token-protected forms)."""
        if not self.csrf_url or not self.csrf_field or data is None:
            return data
        try:
            r = self.session.get(self.csrf_url, timeout=self.timeout, verify=self.verify)
            m = re.search(
                self.csrf_field + r"[\"\']?\s*(?:value|content)=[\"\']([^\"\']+)",
                r.text, re.I)
            if not m:
                m = re.search(r"name=[\"\']" + self.csrf_field +
                              r"[\"\'][^>]*value=[\"\']([^\"\']+)", r.text, re.I)
            if m:
                token = m.group(1)
                if isinstance(data, str):
                    data = data + f"&{self.csrf_field}={token}"
                elif isinstance(data, dict):
                    data[self.csrf_field] = token
        except Exception:
            pass
        return data
