"""ClamAV integration via the clamd INSTREAM protocol (standard library only).

Config ([antivirus] section):
    enabled      = true
    socket       = /var/run/clamav/clamd.ctl    (unix socket)  -- or --
    host / port  = 127.0.0.1 / 3310             (TCP, used when socket is empty)
    fail_mode    = block | allow   what to do if clamd is unreachable
    max_scan_mb  = 50              larger files are not scanned (treated per fail_mode)
    scan_incoming = true           scan attachments when opened/downloaded
    scan_outgoing = true           scan uploads before sending
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading
import time
from collections import OrderedDict
import hashlib

log = logging.getLogger("zoltis.av")

SOCKET_CANDIDATES = ["/var/run/clamav/clamd.ctl", "/run/clamav/clamd.ctl",
                     "/var/run/clamd.scan/clamd.sock", "/run/clamd.scan/clamd.sock",
                     "/var/run/clamav/clamd.sock", "/run/clamav/clamd.sock", "/tmp/clamd.socket"]


class VirusFound(Exception):
    def __init__(self, filename: str, signature: str):
        super().__init__(f"{filename}: {signature}")
        self.filename, self.signature = filename, signature


class ScannerUnavailable(Exception):
    pass


class ClamAV:
    def __init__(self, cfg):
        g = lambda k, d="": os.environ.get(f"ZOLTIS_ANTIVIRUS_{k.upper()}") or cfg.raw.get("antivirus", {}).get(k) or d
        self.enabled = g("enabled", "false").lower() in ("1", "true", "yes", "on")
        self.socket_path = g("socket", "auto")
        self.host = g("host", "127.0.0.1")
        self.port = int(g("port", "3310"))
        self.fail_mode = g("fail_mode", "block").lower()
        self.max_bytes = int(g("max_scan_mb", "50")) * 1024 * 1024
        self.scan_incoming = g("scan_incoming", "true").lower() in ("1", "true", "yes", "on")
        self.scan_outgoing = g("scan_outgoing", "true").lower() in ("1", "true", "yes", "on")
        self.timeout = float(g("timeout", "60"))
        self._cache: OrderedDict[str, str | None] = OrderedDict()
        self._lock = threading.Lock()
        if self.socket_path.lower() in ("-", "none", "tcp"):
            self.socket_path = ""
        elif self.socket_path == "auto":
            self.socket_path = next((p for p in SOCKET_CANDIDATES if os.path.exists(p)), "")

    # -- low level ---------------------------------------------------------
    def _connect(self) -> socket.socket:
        try:
            if self.socket_path:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect(self.socket_path)
            else:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
            return s
        except OSError as e:
            raise ScannerUnavailable(f"clamd not reachable ({self.socket_path or f'{self.host}:{self.port}'}): {e}")

    def _cmd(self, cmd: bytes) -> str:
        with self._connect() as s:
            s.sendall(b"z" + cmd + b"\0")
            return self._read(s)

    @staticmethod
    def _read(s) -> str:
        buf = b""
        while not buf.endswith(b"\0"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf.rstrip(b"\0").decode(errors="replace").strip()

    def ping(self) -> bool:
        try:
            return self._cmd(b"PING") == "PONG"
        except (ScannerUnavailable, OSError):
            return False

    def version(self) -> str:
        try:
            return self._cmd(b"VERSION")
        except (ScannerUnavailable, OSError) as e:
            return f"unavailable: {e}"

    def _instream(self, data: bytes) -> str | None:
        """Return signature name if infected, else None."""
        with self._connect() as s:
            s.sendall(b"zINSTREAM\0")
            view = memoryview(data)
            for i in range(0, len(view), 65536):
                chunk = view[i:i + 65536]
                s.sendall(struct.pack(">I", len(chunk)) + chunk)
            s.sendall(struct.pack(">I", 0))
            res = self._read(s)
        # "stream: OK" | "stream: Eicar-Signature FOUND" | "INSTREAM size limit exceeded. ERROR"
        if res.endswith("FOUND"):
            return res.split(":", 1)[1].rsplit("FOUND", 1)[0].strip()
        if res.endswith("OK"):
            return None
        raise ScannerUnavailable(f"clamd error: {res}")

    # -- public ------------------------------------------------------------
    def scan(self, filename: str, data: bytes) -> dict:
        """Scan bytes. Returns {'status': 'clean'|'infected'|'skipped'|'error', 'signature': ...}.

        Never raises; callers decide via enforce().
        """
        if not self.enabled:
            return {"status": "skipped", "reason": "antivirus disabled"}
        if len(data) > self.max_bytes:
            return {"status": "error", "reason": "file too large to scan"}
        key = hashlib.sha256(data).hexdigest()
        with self._lock:
            if key in self._cache:
                sig = self._cache[key]
                return {"status": "infected", "signature": sig} if sig else {"status": "clean"}
        t = time.time()
        try:
            sig = self._instream(data)
        except (ScannerUnavailable, OSError) as e:
            log.warning("antivirus scan failed for %s: %s", filename, e)
            return {"status": "error", "reason": str(e)}
        with self._lock:
            self._cache[key] = sig
            while len(self._cache) > 2000:
                self._cache.popitem(last=False)
        if sig:
            log.warning("VIRUS %s in %s (%d bytes)", sig, filename, len(data))
            return {"status": "infected", "signature": sig}
        log.debug("scanned %s clean in %.0f ms", filename, (time.time() - t) * 1000)
        return {"status": "clean"}

    def enforce(self, filename: str, data: bytes) -> dict:
        """Scan and raise VirusFound / ScannerUnavailable according to policy."""
        r = self.scan(filename, data)
        if r["status"] == "infected":
            raise VirusFound(filename, r["signature"])
        if r["status"] == "error" and self.fail_mode == "block":
            raise ScannerUnavailable(f"Could not scan {filename} for viruses ({r['reason']}). "
                                     "The file was blocked for safety.")
        return r

    def status(self) -> dict:
        if not self.enabled:
            return {"enabled": False}
        return {"enabled": True, "online": self.ping(), "version": self.version(),
                "fail_mode": self.fail_mode, "scan_incoming": self.scan_incoming,
                "scan_outgoing": self.scan_outgoing}
