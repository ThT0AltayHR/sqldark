"""Parameter discovery: when the user gives a bare URL with no injectable
parameter, crawl the page for links and forms and surface candidate params."""
import re
from urllib.parse import urlparse, urljoin, parse_qsl

HREF = re.compile(r'href=["\']([^"\'#]+)["\']', re.I)
FORM = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.S)
ACTION = re.compile(r'action=["\']([^"\']*)["\']', re.I)
METHOD = re.compile(r'method=["\']([^"\']*)["\']', re.I)
INPUT = re.compile(r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\']', re.I)

# Common parameter names worth probing when nothing else is found.
COMMON = ["id", "cat", "page", "pid", "item", "product", "user", "uid",
          "name", "search", "q", "query", "category", "article", "news"]


class Discovery:
    def __init__(self, http, log, max_links=50):
        self.http = http
        self.log = log
        self.max_links = max_links

    def find(self, base_url):
        """Return a list of candidate target descriptors: {url, method, data}."""
        self.log.info(f"no parameter supplied; crawling {base_url} for injection points")
        resp = self.http.send(base_url, method="GET")
        host = urlparse(base_url).netloc
        candidates = []
        seen = set()

        # 1) Links on the page that carry a query string
        for href in HREF.findall(resp.text)[: self.max_links]:
            full = urljoin(base_url, href)
            if urlparse(full).netloc != host:
                continue
            q = parse_qsl(urlparse(full).query)
            if q and full not in seen:
                seen.add(full)
                candidates.append({"url": full, "method": "GET", "data": None})
                self.log.ok(f"found GET params {[k for k, _ in q]} at {full}")

        # 2) Forms on the page
        for form_html in FORM.findall(resp.text):
            action = ACTION.search(form_html)
            method = (METHOD.search(form_html) or [None, "GET"])
            m = (method.group(1) if hasattr(method, "group") else "GET").upper()
            names = INPUT.findall(form_html)
            if not names:
                continue
            target = urljoin(base_url, action.group(1)) if action else base_url
            data = "&".join(f"{n}=1" for n in names)
            if m == "POST":
                candidates.append({"url": target, "method": "POST", "data": data})
            else:
                sep = "&" if urlparse(target).query else "?"
                candidates.append({"url": f"{target}{sep}{data}", "method": "GET",
                                   "data": None})
            self.log.ok(f"found {m} form -> {target} fields {names}")

        # 3) Fallback: probe the base URL with common parameter names
        if not candidates:
            self.log.warn("no links/forms with parameters; probing common names")
            sep = "&" if urlparse(base_url).query else "?"
            guess = "&".join(f"{p}=1" for p in COMMON)
            candidates.append({"url": f"{base_url}{sep}{guess}", "method": "GET",
                               "data": None})
        return candidates
