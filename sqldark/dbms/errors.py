"""DBMS error-message signatures used for error-based detection and fingerprinting."""
import re

# Each entry: dbms name -> list of regex signatures
ERROR_SIGNATURES = {
    "MySQL": [
        r"SQL syntax.*?MySQL", r"Warning.*?\bmysqli?_",
        r"MySQLSyntaxErrorException", r"valid MySQL result",
        r"check the manual that (corresponds to|fits) your MySQL server version",
        r"Unknown column '[^ ]+' in 'field list'", r"MySqlClient\.",
        r"com\.mysql\.jdbc", r"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
        r"You have an error in your SQL syntax",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*?ERROR", r"Warning.*?\bpg_",
        r"valid PostgreSQL result", r"Npgsql\.",
        r"PG::SyntaxError:", r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
    ],
    "Microsoft SQL Server": [
        r"Driver.*? SQL[\-\_\ ]*Server", r"OLE DB.*? SQL Server",
        r"\bSQL Server[^&lt;&quot;]+Driver", r"Warning.*?\bmssql_",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.SqlException",
        r"Unclosed quotation mark after the character string",
        r"Microsoft SQL Native Client error",
    ],
    "Microsoft Access": [
        r"Microsoft Access (\d+ )?Driver", r"JET Database Engine",
        r"Access Database Engine", r"ODBC Microsoft Access",
    ],
    "Oracle": [
        r"\bORA-\d{5}", r"Oracle error", r"Oracle.*?Driver",
        r"Warning.*?\boci_", r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException", r"Warning.*?\bsqlite_",
        r"\[SQLITE_ERROR\]", r"SQLITE_ERROR", r"sqlite3.OperationalError",
        r"unrecognized token:",
    ],
    "IBM DB2": [
        r"CLI Driver.*?DB2", r"DB2 SQL error", r"\bdb2_\w+\(",
        r"SQLCODE[=:\d, -]+SQLSTATE",
    ],
    "Firebird": [
        r"Dynamic SQL Error", r"Warning.*?\bibase_",
    ],
}

_COMPILED = {db: [re.compile(p, re.IGNORECASE) for p in pats]
             for db, pats in ERROR_SIGNATURES.items()}


def match_dbms(text):
    """Return dbms name if an error signature is found, else None."""
    if not text:
        return None
    for db, pats in _COMPILED.items():
        for p in pats:
            if p.search(text):
                return db
    return None
