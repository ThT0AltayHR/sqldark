"""Colored, leveled, timestamped console logging (sqlmap-style, but richer)."""
import sys
import time

RESET = "\033[0m"
BOLD = "\033[1m"
COLORS = {
    "INFO":     "\033[94m",
    "SUCCESS":  "\033[92m",
    "WARNING":  "\033[93m",
    "ERROR":    "\033[91m",
    "CRITICAL": "\033[95m",
    "PAYLOAD":  "\033[96m",
    "DEBUG":    "\033[90m",
}
# Full level word shown in the line, like sqlmap's [INFO]/[WARNING]/[CRITICAL].
LEVEL_WORD = {
    "INFO": "INFO", "SUCCESS": "SUCCESS", "WARNING": "WARNING",
    "ERROR": "ERROR", "CRITICAL": "CRITICAL", "PAYLOAD": "PAYLOAD", "DEBUG": "DEBUG",
}


class Logger:
    def __init__(self, verbose=1, use_color=True):
        self.verbose = verbose
        self.use_color = use_color and sys.stdout.isatty()

    def _stamp(self):
        return time.strftime("%H:%M:%S")

    def _c(self, level, text):
        if not self.use_color:
            return text
        return f"{COLORS.get(level, '')}{text}{RESET}"

    def _emit(self, level, msg, min_v=1):
        if self.verbose < min_v:
            return
        word = LEVEL_WORD.get(level, level)
        stamp = self._c("DEBUG", f"[{self._stamp()}]")
        tag = self._c(level, f"[{word}]")
        print(f"{stamp} {tag} {msg}")

    # Public API (keeps old names as aliases so existing calls work)
    def info(self, msg):     self._emit("INFO", msg)
    def ok(self, msg):       self._emit("SUCCESS", msg)
    def success(self, msg):  self._emit("SUCCESS", msg)
    def warn(self, msg):     self._emit("WARNING", msg)
    def warning(self, msg):  self._emit("WARNING", msg)
    def error(self, msg):    self._emit("ERROR", msg)
    def crit(self, msg):     self._emit("CRITICAL", msg)
    def critical(self, msg): self._emit("CRITICAL", msg)
    def payload(self, msg):  self._emit("PAYLOAD", msg, min_v=2)
    def debug(self, msg):    self._emit("DEBUG", msg, min_v=3)

    def banner(self, text):
        print(self._c("CRITICAL", text))
