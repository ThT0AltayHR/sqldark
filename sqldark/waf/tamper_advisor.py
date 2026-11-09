"""Map a detected WAF to a recommended tamper chain.

When SQLDark fingerprints a WAF and the user did not pin --tamper, the engine
can auto-load a chain known to help against that product. These mirror the
community wisdom captured in sqlmap's per-WAF notes, adapted to SQLDark's
tamper names."""

# Chains are ordered: cheapest / most compatible first.
WAF_TAMPERS = {
    "Cloudflare": ["space2comment", "charencode", "randomcase", "space2randomblank"],
    "ModSecurity": ["modsecurityversioned", "space2comment", "randomcomments"],
    "ModSecurity CRS": ["modsecurityversioned", "space2hash", "randomcase"],
    "PHPIDS": ["randomcase", "space2comment", "charunicodeencode", "equaltolike"],
    "Imperva Incapsula": ["space2comment", "charencode", "charunicodeencode", "randomcase"],
    "AWS WAF / CloudFront": ["space2comment", "randomcase", "between"],
    "F5 BIG-IP ASM": ["space2comment", "randomcase", "charencode"],
    "Citrix NetScaler": ["space2plus", "randomcase", "charencode"],
    "Barracuda": ["space2comment", "randomcase", "appendnullbyte"],
    "Sucuri": ["space2comment", "randomcase", "charencode"],
    "Wordfence": ["randomcase", "space2comment", "charencode"],
    "FortiWeb": ["space2comment", "randomcase", "between", "charencode"],
    "Akamai": ["space2randomblank", "randomcase", "charencode"],
    "DDoS-Guard": ["space2comment", "randomcase"],
    "NAXSI": ["charunicodeencode", "randomcase", "space2comment"],
    "WebKnight": ["space2comment", "charencode", "randomcase"],
    "Comodo WAF": ["space2comment", "randomcase", "equaltolike"],
    "Safedog": ["space2comment", "randomcase", "halfversionedmorekeywords"],
    "AliYunDun": ["space2comment", "randomcase", "charencode"],
    "SonicWall": ["space2comment", "randomcase"],
    "Reblaze": ["space2randomblank", "randomcase", "charencode"],
}

# A generic fallback chain when the WAF is unknown but blocking.
GENERIC = ["space2comment", "randomcase", "charencode", "between"]


def recommend(waf_name):
    """Return a tamper-name list for the given WAF (or the generic chain)."""
    if not waf_name:
        return []
    if waf_name in WAF_TAMPERS:
        return list(WAF_TAMPERS[waf_name])
    return list(GENERIC)
