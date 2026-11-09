"""Export dumped databases to a zip archive, named after the target site.

Layout inside <base>/database/<host>/:
    <host>.zip
        <db>/<table>.csv     one CSV per table (original column/table names kept)
        manifest.json        dbms, banner, counts, timestamp
"""
import csv
import io
import json
import os
import time
import zipfile
from urllib.parse import urlparse


def _host_of(target):
    try:
        h = urlparse(target).hostname or "target"
    except Exception:
        h = "target"
    return h.replace(":", "_")


def export_dump_to_zip(target, result, base=None, label=None):
    """Write `result` (from run_enumeration) to a zip in the database dir.
    Table and database names are preserved exactly (no renaming)."""
    base = base or os.path.join(os.getcwd(), ".sqldark")
    host = _host_of(target)
    name = label or host
    outdir = os.path.join(base, "database", host)
    os.makedirs(outdir, exist_ok=True)
    zip_path = os.path.join(outdir, name + ".zip")

    manifest = {
        "target": target,
        "host": host,
        "dbms": result.get("dbms"),
        "banner": result.get("banner"),
        "current_db": result.get("current_db"),
        "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tables": {},
    }

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for db, tables in (result.get("databases") or {}).items():
            for table, node in tables.items():
                cols = node.get("columns") or []
                rows = node.get("rows") or []
                manifest["tables"][f"{db}.{table}"] = {
                    "columns": cols, "row_count": len(rows)}
                buf = io.StringIO()
                if cols:
                    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
                    w.writeheader()
                    for r in rows:
                        w.writerow(r)
                else:
                    buf.write("\n".join(str(r) for r in rows))
                z.writestr(f"{db}/{table}.csv", buf.getvalue())
        z.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
    return zip_path
