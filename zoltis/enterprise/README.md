# zoltis.enterprise

This directory holds the **Enterprise Edition** package (calendar, contacts, drive, mobile API, admin, SSO).
It is removed from Community builds by `build.sh`. When it's absent or unlicensed, Zoltis Mail runs as Community Edition.

Contract (see docs/ARCHITECTURE.md):
    verify_license(path) -> dict   # raise on invalid/expired
    load(license_info) -> list of modules with .name, .features, .register(router)
