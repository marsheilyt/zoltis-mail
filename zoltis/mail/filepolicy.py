"""Attachment security policy: blocks risky file types in email attachments,
inside archives (zipped folders) and in folders uploaded from the browser.

Checks, in order:
  1. File name tricks: right-to-left override characters, trailing dots/spaces,
     double extensions that hide an executable (invoice.pdf.exe), very long names.
  2. Extension against the blocked list (executables, scripts, installers,
     shortcuts, disk images, ...).
  3. Real content (magic bytes), so renamed files are caught: Windows PE (MZ),
     ELF, Mach-O, Java class, Windows shortcut, CAB, ISO, scripts with #!.
  4. Archives (zip, jar-like, tar, tar.gz/bz2/xz, gz): every entry is checked
     recursively up to `archive_max_depth`; password-protected archives, zip bombs
     and archives with too many files are handled by policy.
  5. Office documents with macros (docm/xlsm/... or a .docx that secretly
     contains vbaProject.bin).

Verdicts: "allow", "warn" (user is cautioned), "block".
Only the standard library is used.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import re
import tarfile
import unicodedata
import zipfile

# Based on the lists used by large mail providers.
DEFAULT_BLOCKED = (
    # Gmail's blocked list
    "ade adp apk appx appxbundle bat cab chm cmd com cpl diagcab diagcfg diagpack dll dmg ex ex_ exe hta img "
    "ins iso isp jar jnlp js jse lib lnk mde msc msi msix msixbundle msp mst nsh pif ps1 scr sct shb sys vb vbe "
    "vbs vhd vxd wsc wsf wsh xll "
    # plus other Windows code / installer / shortcut types blocked by Outlook
    "application appref-ms bas gadget hlp inf msh msh1 msh2 mshxml msh1xml msh2xml msu ps1xml ps2 ps2xml psc1 "
    "psc2 psd1 psdm1 reg scf settingcontent-ms url vhdx website ws xbap"
).split()
# Added when strict_scripts = true (developer teams usually need these)
UNIX_RISKY = "sh bash zsh csh ksh run bin command action workflow pkg mpkg deb rpm appimage py pyc pyo pyw pyz pl ps".split()
MACRO_OFFICE = "docm dotm xlsm xltm xlam xlsb pptm potm ppam ppsm sldm".split()
ARCHIVE_EXT = {"zip", "jar", "war", "ear", "tar", "tgz", "tbz", "tbz2", "txz", "gz", "bz2", "xz",
               "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"}
OPAQUE_ARCHIVES = {"rar", "7z", "arj", "lzh", "lha", "ace", "zipx", "cpio", "z"}
OFFICE_ZIP = {"docx", "dotx", "xlsx", "xltx", "pptx", "potx", "ppsx", "docm", "dotm", "xlsm", "xltm", "pptm", "potm", "ppsm"}
BIDI_CHARS = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩", "‎", "‏"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "zip", "csv", "rtf", "htm", "html"}

LEVEL = {"allow": 0, "warn": 1, "block": 2}


def _norm_ext_list(s: str) -> set[str]:
    return {x.strip().lower().lstrip(".") for x in re.split(r"[,\s]+", s or "") if x.strip()}


class Finding:
    __slots__ = ("level", "path", "reason")

    def __init__(self, level, path, reason):
        self.level, self.path, self.reason = level, path, reason

    def as_dict(self):
        return {"level": self.level, "path": self.path, "reason": self.reason}


class FilePolicy:
    def __init__(self, cfg=None):
        raw = (cfg.raw.get("attachments", {}) if cfg is not None else {})

        def g(key, default):
            v = os.environ.get(f"ZOLTIS_ATTACHMENTS_{key.upper()}")
            if v is None:
                v = raw.get(key)
            return default if v in (None, "") else v

        def gb(key, default):
            return str(g(key, default)).lower() in ("1", "true", "yes", "on")

        self.enabled = gb("enabled", "true")
        blocked = _norm_ext_list(g("blocked_extensions", "")) or set(DEFAULT_BLOCKED)
        blocked |= _norm_ext_list(g("extra_blocked_extensions", ""))
        if gb("strict_scripts", "false"):
            blocked |= set(UNIX_RISKY)
        self.allowed = _norm_ext_list(g("allowed_extensions", ""))  # explicit exceptions
        self.blocked = blocked - self.allowed
        self.macro_action = g("macro_documents", "warn").lower()          # allow | warn | block
        self.encrypted_action = g("encrypted_archives", "block").lower()   # allow | warn | block
        self.opaque_action = g("uninspectable_archives", "warn").lower()   # rar/7z we can't open
        self.content_detection = gb("detect_executables_by_content", "true")
        self.scan_archives = gb("scan_archives", "true")
        self.max_depth = int(g("archive_max_depth", "3"))
        self.max_files = int(g("archive_max_files", "5000"))
        self.max_uncompressed = int(g("archive_max_uncompressed_mb", "1024")) * 1024 * 1024
        self.max_ratio = int(g("archive_max_ratio", "200"))
        self.incoming_action = g("incoming_action", "block").lower()       # block | warn
        self.apply_outgoing = gb("check_outgoing", "true")
        self.apply_incoming = gb("check_incoming", "true")

    # ------------------------------------------------------------------ public
    def public(self) -> dict:
        """What the browser needs for instant checks while composing."""
        return {
            "enabled": self.enabled,
            "blocked_extensions": sorted(self.blocked),
            "macro_extensions": MACRO_OFFICE,
            "macro_action": self.macro_action,
            "scan_archives": self.scan_archives,
            "encrypted_archives": self.encrypted_action,
            "incoming_action": self.incoming_action,
            "archive_max_depth": self.max_depth,
        }

    def check(self, filename: str, data: bytes | None = None) -> dict:
        """Return {'verdict': allow|warn|block, 'findings': [...], 'summary': str}."""
        if not self.enabled:
            return {"verdict": "allow", "findings": [], "summary": ""}
        findings: list[Finding] = []
        budget = {"files": 0, "bytes": 0}
        self._check_one(filename or "unnamed", data, findings, depth=0, path=filename or "unnamed", budget=budget)
        verdict = "allow"
        for f in findings:
            if LEVEL[f.level] > LEVEL[verdict]:
                verdict = f.level
        top = next((f for f in findings if f.level == verdict), None)
        return {"verdict": verdict, "findings": [f.as_dict() for f in findings[:50]],
                "summary": (f"{top.path}: {top.reason}" if top and top.path != filename else (top.reason if top else ""))}

    def check_names(self, names: list[str]) -> dict:
        """Check a list of paths (e.g. a folder upload) by name only."""
        out = {}
        for n in names:
            out[n] = self.check(n, None)
        return out

    # ------------------------------------------------------------- internals
    @staticmethod
    def _exts(name: str) -> list[str]:
        base = name.replace("\\", "/").rsplit("/", 1)[-1]
        parts = base.lower().split(".")
        return [p for p in parts[1:] if p] if len(parts) > 1 else []

    def _name_checks(self, name: str, path: str, findings: list):
        if any(c in BIDI_CHARS for c in name):
            findings.append(Finding("block", path, "file name uses hidden text-direction characters to disguise its type"))
        clean = unicodedata.normalize("NFKC", "".join(c for c in name if c not in BIDI_CHARS))
        base = clean.replace("\\", "/").rsplit("/", 1)[-1]
        stripped = base.rstrip(" .")
        if stripped != base and "." in stripped:
            findings.append(Finding("block", path, "file name ends with dots or spaces to hide its real type"))
        exts = self._exts(stripped)
        if not exts:
            return None
        ext = exts[-1]
        if ext in self.allowed:
            return ext
        if ext in self.blocked:
            if len(exts) >= 2 and exts[-2] in DECOY_EXT:
                findings.append(Finding("block", path, f"disguised program: looks like .{exts[-2]} but is .{ext}"))
            elif re.search(r"\s{5,}\.", stripped):
                findings.append(Finding("block", path, f"name padded with spaces to hide the .{ext} extension"))
            else:
                findings.append(Finding("block", path, f".{ext} files can run code and are blocked for security"))
        elif ext in MACRO_OFFICE and self.macro_action != "allow":
            findings.append(Finding(self.macro_action, path, f"Office document with macros (.{ext})"))
        elif ext in OPAQUE_ARCHIVES and self.opaque_action != "allow":
            findings.append(Finding(self.opaque_action, path, f".{ext} archives can't be inspected; contents unknown"))
        return ext

    def _content_kind(self, data: bytes):
        """Return (description, level) if the bytes are executable content."""
        h = data[:64]
        if h[:2] == b"MZ" and len(data) > 0x40:
            return "a Windows program (PE executable)", "block"
        if h[:4] == b"\x7fELF":
            return "a Linux program (ELF executable)", "block"
        if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
            return "a macOS program (Mach-O)", "block"
        if h[:4] == b"\xca\xfe\xba\xbe" and len(data) > 8 and data[7] > 40:
            return "a Java class file", "block"
        if h[:20] == b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46":
            return "a Windows shortcut (.lnk)", "block"
        if h[:4] == b"MSCF":
            return "a Windows cabinet installer", "block"
        if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
            return "a disc image (ISO)", "block"
        if b"<hta:application" in data[:4096].lower():
            return "an HTML application (HTA)", "block"
        if h[:2] == b"#!":
            return "an executable script", "warn"
        return None

    def _check_one(self, name, data, findings, depth, path, budget):
        ext = self._name_checks(name, path, findings)
        if data is None:
            return
        if self.content_detection and ext not in self.allowed:
            kind = self._content_kind(data)
            if kind and (ext is None or ext not in self.blocked):
                desc, level = kind
                if level == "warn" and (ext is None or ext in UNIX_RISKY):
                    findings.append(Finding(level, path, "file is an executable script"))
                else:
                    findings.append(Finding(level, path, f"file is really {desc}" + (f" renamed to .{ext}" if ext else "")))
        if not self.scan_archives:
            return
        if depth >= self.max_depth:
            if self._is_archive(ext, data):
                findings.append(Finding("block", path, f"archives nested more than {self.max_depth} levels deep"))
            return
        try:
            if zipfile.is_zipfile(io.BytesIO(data)):
                self._zip(data, ext, findings, depth, path, budget)
            elif ext in ("tar", "tgz", "tbz", "tbz2", "txz") or path.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz")) or self._is_tar(data):
                self._tar(data, findings, depth, path, budget)
            elif data[:2] == b"\x1f\x8b" or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00":
                self._single(data, name, findings, depth, path, budget)
            elif data[:4] == b"Rar!" or data[:6] == b"7z\xbc\xaf\x27\x1c":
                if self.opaque_action != "allow" and ext not in OPAQUE_ARCHIVES:
                    findings.append(Finding(self.opaque_action, path, "RAR/7z archive can't be inspected; contents unknown"))
        except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, lzma.LZMAError, ValueError, RuntimeError):
            findings.append(Finding("warn", path, "damaged archive; contents could not be checked"))

    @staticmethod
    def _is_tar(data):
        return len(data) > 262 and data[257:262] == b"ustar"

    def _is_archive(self, ext, data):
        return (ext in ARCHIVE_EXT) or zipfile.is_zipfile(io.BytesIO(data)) or self._is_tar(data) or data[:2] == b"\x1f\x8b"

    def _account(self, budget, size, path, findings, compressed=None):
        budget["files"] += 1
        budget["bytes"] += size
        if budget["files"] > self.max_files:
            findings.append(Finding("block", path, f"archive contains more than {self.max_files} files"))
            return False
        if budget["bytes"] > self.max_uncompressed:
            findings.append(Finding("block", path, "archive expands to an unsafe size (possible zip bomb)"))
            return False
        if compressed and size > 10 * 1024 * 1024 and size / max(1, compressed) > self.max_ratio:
            findings.append(Finding("block", path, "suspicious compression ratio (possible zip bomb)"))
            return False
        return True

    def _zip(self, data, ext, findings, depth, path, budget):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            names = {i.filename for i in infos}
            is_office = ext in OFFICE_ZIP or "[Content_Types].xml" in names
            if is_office:
                if any(n.lower().endswith("vbaproject.bin") for n in names) and self.macro_action != "allow" and ext not in MACRO_OFFICE:
                    findings.append(Finding(self.macro_action, path, "document contains macros (hidden VBA code)"))
                if any(n.lower().endswith((".exe", ".dll", ".scr", ".bat", ".js", ".vbs")) for n in names):
                    findings.append(Finding("block", path, "document has an embedded program"))
                return
            encrypted = [i for i in infos if i.flag_bits & 0x1]
            if encrypted and self.encrypted_action != "allow":
                findings.append(Finding(self.encrypted_action, path,
                                        "password-protected archive; contents can't be scanned"))
            for info in infos:
                if info.is_dir():
                    self._name_checks(info.filename.rstrip("/"), f"{path}/{info.filename}", [])
                    continue
                inner = f"{path}/{info.filename}"
                if not self._account(budget, info.file_size, inner, findings, info.compress_size):
                    return
                if ".." in info.filename.replace("\\", "/").split("/") or info.filename.startswith("/"):
                    findings.append(Finding("block", inner, "archive tries to write outside its folder (path traversal)"))
                    continue
                if info.flag_bits & 0x1:
                    self._name_checks(info.filename, inner, findings)
                    continue
                try:
                    with z.open(info) as fh:
                        content = fh.read(min(info.file_size, 64 * 1024 * 1024) + 1)
                except (RuntimeError, NotImplementedError, zipfile.BadZipFile, OSError, EOFError):
                    self._name_checks(info.filename, inner, findings)
                    continue
                self._check_one(info.filename, content, findings, depth + 1, inner, budget)

    def _tar(self, data, findings, depth, path, budget):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
            for m in t:
                inner = f"{path}/{m.name}"
                if m.isdir():
                    continue
                if m.issym() or m.islnk():
                    if m.linkname.startswith("/") or ".." in m.linkname.split("/"):
                        findings.append(Finding("block", inner, "archive contains a link pointing outside its folder"))
                    continue
                if ".." in m.name.split("/") or m.name.startswith("/"):
                    findings.append(Finding("block", inner, "archive tries to write outside its folder (path traversal)"))
                    continue
                if not m.isfile():
                    continue
                if m.mode & 0o111:
                    findings.append(Finding("warn", inner, "file is marked executable"))
                if not self._account(budget, m.size, inner, findings):
                    return
                fh = t.extractfile(m)
                content = fh.read(min(m.size, 64 * 1024 * 1024)) if fh else b""
                self._check_one(m.name, content, findings, depth + 1, inner, budget)

    def _single(self, data, name, findings, depth, path, budget):
        if data[:2] == b"\x1f\x8b":
            opener = gzip.GzipFile(fileobj=io.BytesIO(data))
        elif data[:3] == b"BZh":
            opener = bz2.BZ2File(io.BytesIO(data))
        else:
            opener = lzma.LZMAFile(io.BytesIO(data))
        with opener as fh:
            content = fh.read(self.max_uncompressed + 1)
        if not self._account(budget, len(content), path, findings, len(data)):
            return
        inner_name = re.sub(r"\.(gz|bz2|xz|tgz|tbz2?|txz)$", "", name, flags=re.I) or "content"
        if name.lower().endswith((".tgz", ".tbz", ".tbz2", ".txz")):
            inner_name += ".tar"
        if self._is_tar(content):
            self._tar(content, findings, depth, path, budget)
        else:
            self._check_one(inner_name, content, findings, depth + 1, f"{path}/{inner_name}", budget)
