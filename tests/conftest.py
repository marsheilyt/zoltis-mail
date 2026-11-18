"""Shared fixtures: a throwaway licensing signing key and a mock licensing portal."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "devtools"))

import pytest  # noqa: E402

import license_dev  # noqa: E402
from zoltis import licensing  # noqa: E402

TEST_KID = "test"

# The licensing tests exercise enforcement, which is off by default.
os.environ.setdefault("ZOLTIS_LICENSE_REQUIRED", "true")
# The source tree under test isn't a signed release; test_integrity.py covers the code check.
os.environ.setdefault("ZOLTIS_INTEGRITY_ENFORCE", "false")
# Most tests check behaviour after the 7-day registration period; test_license.py covers the period itself.
os.environ.setdefault("ZOLTIS_LICENSE_GRACE_DAYS", "0")


@pytest.fixture(scope="session")
def portal():
    """Trust a test signing key and run a mock portal; ZOLTIS_LICENSE_SERVER points at it."""
    seed = os.urandom(32)
    licensing.TRUSTED_KEYS[TEST_KID] = licensing.ed25519_public_key(seed).hex()
    p = license_dev.MockPortal(seed, TEST_KID)
    p.url = p.serve()
    os.environ["ZOLTIS_LICENSE_SERVER"] = p.url
    p.issue = lambda *domains, **kw: license_dev.issue_key(seed, TEST_KID, domains, **kw)
    yield p
    p.httpd.shutdown()
    licensing.TRUSTED_KEYS.pop(TEST_KID, None)
