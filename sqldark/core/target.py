"""Target parsing and injection-point construction."""
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

MARKER = "*"


class InjectionPoint:
    """One place a payload can be injected (a GET/POST param or a custom *)."""
    def __init__(self, place, name, base_value, template, method):
        self.place = place        # 'GET' | 'POST' | 'URI'
        self.name = name
        self.base_value = base_value
        self.template = template  # callable(payload) -> (url, data)
        self.method = method

    def build(self, payload):
        return self.template(self.base_value + payload if self.base_value is not None
                             else payload)

    def build_raw(self, value):
        return self.template(value)

    def __repr__(self):
        return f"<InjectionPoint {self.place}:{self.name}>"


class Target:
    def __init__(self, url, method="GET", data=None):
        self.url = url
        self.method = method.upper()
        self.data = data
        self.points = []
        self._parse()

    def _parse(self):
        parsed = urlparse(self.url)

        # Explicit marker in URL
        if MARKER in self.url:
            self._marker_point(parsed)
            return

        # GET params
        q = parse_qsl(parsed.query, keep_blank_values=True)
        for i, (k, v) in enumerate(q):
            self.points.append(self._get_point(parsed, q, i, k, v))

        # POST params
        if self.data:
            d = parse_qsl(self.data, keep_blank_values=True)
            for i, (k, v) in enumerate(d):
                self.points.append(self._post_point(parsed, d, i, k, v))

    def _marker_point(self, parsed):
        url = self.url
        def tmpl(value):
            return url.replace(MARKER, value), self.data
        self.points.append(InjectionPoint("URI", "marker", "", tmpl, self.method))

    def _get_point(self, parsed, pairs, idx, key, val):
        def tmpl(value, _idx=idx):
            new = list(pairs)
            new[_idx] = (new[_idx][0], value)
            qs = urlencode(new)
            rebuilt = urlunparse(parsed._replace(query=qs))
            return rebuilt, self.data
        return InjectionPoint("GET", key, val, tmpl, "GET")

    def _post_point(self, parsed, pairs, idx, key, val):
        base_url = urlunparse(parsed)
        def tmpl(value, _idx=idx):
            new = list(pairs)
            new[_idx] = (new[_idx][0], value)
            return base_url, urlencode(new)
        return InjectionPoint("POST", key, val, tmpl, "POST")
