"""SQLDark command-line interface."""
import argparse
import sys

from sqldark import __version__, BANNER
from sqldark.core.logger import Logger
from sqldark.core.http import HttpClient
from sqldark.core.engine import Engine, DEFAULT_ORDER
from sqldark import tamper as tamper_mod
from sqldark.session.store import SessionStore
from sqldark.session.exporter import export_dump_to_zip


def build_parser():
    p = argparse.ArgumentParser(
        prog="sqldark",
        description="SQLDark - advanced SQL injection & database takeover framework",
        epilog="Use only on systems you own or are authorized to test.",
    )
    tgt = p.add_argument_group("target")
    tgt.add_argument("-u", "--url", help="target URL (use * to mark an injection point)")
    tgt.add_argument("--data", help="POST data string (a=1&b=2)")
    tgt.add_argument("-m", "--method", default=None, help="HTTP method override")

    req = p.add_argument_group("request")
    req.add_argument("--cookie", help="HTTP Cookie header")
    req.add_argument("-H", "--header", action="append", default=[],
                     help="extra header 'Name: value' (repeatable)")
    req.add_argument("--proxy", help="proxy url e.g. http://127.0.0.1:8080")
    req.add_argument("--timeout", type=float, default=15)
    req.add_argument("--delay", type=float, default=0.0, help="delay between requests (s)")
    req.add_argument("--retries", type=int, default=2)
    req.add_argument("--random-agent", action="store_true", help="rotate User-Agent")
    req.add_argument("--random-delay", type=float, default=0.0,
                     help="add up to N seconds of random jitter per request (human-like)")
    req.add_argument("--csrf-url", help="URL to fetch a fresh anti-CSRF token from")
    req.add_argument("--csrf-token", dest="csrf_field",
                     help="name of the anti-CSRF token field to refresh")

    det = p.add_argument_group("detection")
    det.add_argument("--technique", default=DEFAULT_ORDER,
                     help=f"technique letters to use (default {DEFAULT_ORDER}: "
                          "E=error B=boolean U=union T=time)")
    det.add_argument("--skip-waf", action="store_true", help="skip WAF fingerprinting")
    det.add_argument("--level", type=int, default=1, choices=range(1,6),
                     help="1-5: how many payload-library boundaries to try (wider=deeper)")
    det.add_argument("--risk", type=int, default=1, choices=range(1,4),
                     help="1-3: payload families to try (1 AND-based; 2 adds "
                          "OR-based; 3 adds heavier time vectors) - labs only")

    ev = p.add_argument_group("evasion")
    ev.add_argument("--tamper", help="comma-separated tamper scripts")
    ev.add_argument("--list-tampers", action="store_true", help="list tamper scripts and exit")
    ev.add_argument("--auto-tamper", action="store_true",
                    help="auto-pick a tamper chain from the detected WAF")

    enu = p.add_argument_group("enumeration")
    enu.add_argument("-b", "--banner", action="store_true", help="retrieve DBMS banner/version")
    enu.add_argument("--current-db", action="store_true", help="retrieve current database name")
    enu.add_argument("--tables", action="store_true", help="enumerate tables")
    enu.add_argument("--columns", action="store_true", help="enumerate columns")
    enu.add_argument("--dump", action="store_true", help="dump rows of the target table")
    enu.add_argument("--dump-all", action="store_true",
                     help="dump every table of the current database")
    enu.add_argument("-D", dest="db", help="database to enumerate")
    enu.add_argument("-T", dest="table", help="table to target")
    enu.add_argument("--max-rows", type=int, default=50, help="max rows to dump")

    out = p.add_argument_group("output")
    out.add_argument("-v", "--verbose", action="count", default=1,
                     help="increase verbosity (-vv, -vvv)")
    out.add_argument("-q", "--quiet", action="store_true")
    out.add_argument("--no-color", action="store_true")
    out.add_argument("--no-banner", action="store_true")
    p.add_argument("--version", action="version", version=f"sqldark {__version__}")

    ses = p.add_argument_group("session")
    ses.add_argument("--session", metavar="NAME",
                     help="save results to / resume from a named session (sezon)")
    ses.add_argument("--list-sessions", action="store_true",
                     help="list saved sessions and exit")
    ses.add_argument("--delete-session", metavar="NAME",
                     help="delete a saved session and exit")
    ses.add_argument("--export", action="store_true",
                     help="export dumped databases to a zip (named after the site)")
    return p


def parse_headers(items):
    headers = {}
    for h in items:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    verbose = 0 if args.quiet else args.verbose
    log = Logger(verbose=verbose, use_color=not args.no_color)

    if not args.no_banner and not args.quiet:
        log.banner(BANNER.format(version=__version__))

    if args.list_tampers:
        for name, desc in tamper_mod.available().items():
            print(f"  {name:<22} {desc}")
        return 0

    if args.list_sessions:
        store = SessionStore()
        rows = store.list()
        if not rows:
            log.info("no saved sessions")
        for r in rows:
            log.info(f"{r['name']:<20} {r['dbms']:<12} {r['saved_at']}  {r['target']}")
        return 0

    if args.delete_session:
        store = SessionStore()
        ok = store.delete(args.delete_session)
        log.ok(f"deleted session {args.delete_session}") if ok else \
            log.warn(f"no such session: {args.delete_session}")
        return 0

    if not args.url:
        parser.error("a target is required (-u/--url)")

    tampers = []
    if args.tamper:
        try:
            tampers = tamper_mod.get(args.tamper.split(","))
            log.info("tamper chain: " + " -> ".join(t.name for t in tampers))
        except KeyError as e:
            log.error(str(e))
            return 2

    method = args.method or ("POST" if args.data else "GET")
    http = HttpClient(
        log, timeout=args.timeout, delay=args.delay, retries=args.retries,
        proxy=args.proxy, headers=parse_headers(args.header),
        cookies=args.cookie, tampers=tampers, random_agent=args.random_agent,
        random_delay=args.random_delay, csrf_url=args.csrf_url,
        csrf_field=args.csrf_field,
    )

    store = SessionStore() if (args.session or args.export) else None
    if args.session and store.load(args.session):
        prior = store.load(args.session)
        log.info(f"resuming session '{args.session}' "
                 f"(saved {prior.get('_saved_at','?')}, DBMS {prior.get('dbms','?')})")

    engine = Engine(http, log, techniques=args.technique, skip_waf=args.skip_waf,
                    auto_tamper=getattr(args, 'auto_tamper', False),
                    level=args.level, risk=args.risk)
    enum_opts = {
        "banner": args.banner, "current_db": args.current_db,
        "tables": args.tables, "columns": args.columns, "dump": args.dump,
        "dump_all": args.dump_all,
        "db": args.db, "table": args.table, "max_rows": args.max_rows,
    }
    try:
        findings = engine.scan(args.url, method=method, data=args.data,
                               enum_opts=enum_opts)
    except KeyboardInterrupt:
        log.warn("interrupted by user")
        return 130

    enum_result = getattr(engine, "last_enum", None)
    if args.session and store is not None:
        payload = {"target": args.url, "method": method}
        if enum_result:
            payload.update(enum_result)
        path = store.save(args.session, payload)
        log.ok(f"session saved: {path}")
    if args.export and enum_result:
        zp = export_dump_to_zip(args.url, enum_result, label=args.session)
        log.ok(f"database exported: {zp}")

    return 0 if findings else 1


if __name__ == "__main__":
    sys.exit(main())
