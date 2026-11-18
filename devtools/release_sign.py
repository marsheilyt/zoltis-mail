#!/usr/bin/env python3
"""Sign a Zoltis Mail release: writes zoltis/RELEASE.manifest (SHA-256 of every core file, signed).

    python3 devtools/release_sign.py --seed <release private key hex> --kid k1
    python3 devtools/release_sign.py --check          # show what a running server would report

Run it on the exact release tree (after the last change, before tagging/building). Any later
change to zoltis/ or web/ makes servers report "modified" and, when enforced, lock themselves.
The public half of the key must be in zoltis/licensing.py TRUSTED_KEYS. NEVER commit the seed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from zoltis import __version__  # noqa: E402
from zoltis import integrity as I  # noqa: E402

WEB = os.path.join(ROOT, "web")
PKG = os.path.join(ROOT, "zoltis")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", help="release signing key (64 hex chars); or env ZOLTIS_RELEASE_SEED")
    ap.add_argument("--kid", default="k1")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if a.check:
        print(json.dumps(I.verify(PKG, WEB, __version__), indent=2))
        return
    seed = a.seed or os.environ.get("ZOLTIS_RELEASE_SEED")
    if not seed:
        sys.exit("give --seed or ZOLTIS_RELEASE_SEED")
    files = I.compute(PKG, WEB)
    with open(os.path.join(PKG, I.MANIFEST_NAME), "w") as f:
        f.write(I.sign_manifest(files, __version__, bytes.fromhex(seed), a.kid) + "\n")
    print(f"signed {len(files)} files for version {__version__} (fingerprint {I.fingerprint(files)[:16]}…)")


if __name__ == "__main__":
    main()
