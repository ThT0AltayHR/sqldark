"""Intentionally vulnerable local app to validate SQLDark. LOCAL TESTING ONLY."""
import sqlite3, time, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


def make_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.create_function("sleep", 1, lambda n: time.sleep(float(n)) or 0)
    db.executescript("""
        CREATE TABLE products(id INTEGER, name TEXT, price TEXT);
        INSERT INTO products VALUES (1,'Laptop','999'),(2,'Mouse','25'),(3,'Keyboard','60');
        CREATE TABLE users(id INTEGER, username TEXT, password TEXT);
        INSERT INTO users VALUES (1,'admin','s3cr3t'),(2,'muhammed','sqldark123');
    """)
    return db


DB = make_db()
LOCK = threading.Lock()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path != "/product":
            self.send_response(404); self.end_headers()
            self.wfile.write(b"not found"); return
        qs = parse_qs(u.query, keep_blank_values=True)
        pid = qs.get("id", ["1"])[0]
        # VULNERABLE: raw string concatenation, numeric context (unquoted)
        sql = f"SELECT id,name,price FROM products WHERE id = {pid}"
        try:
            with LOCK:
                rows = DB.execute(sql).fetchall()
            body = "<html><body><h1>Store</h1>"
            for r in rows:
                body += f"<div class='product'>Name: {r[1]} - Price: {r[2]}</div>"
            if not rows:
                body += "<div>no products</div>"
            body += "</body></html>"
            self.send_response(200)
        except Exception as e:
            body = f"<html><body>SQLite error: unrecognized token / {e}</body></html>"
            self.send_response(500)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


def run(port=8899):
    HTTPServer(("127.0.0.1", port), H).serve_forever()


if __name__ == "__main__":
    run()
