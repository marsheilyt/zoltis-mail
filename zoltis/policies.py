"""Zoltis Mail Community Edition policies that the administrator must accept.

The text ships in web/legal/ (so it is covered by the code-integrity check and can't be edited on a
server). The first admin accepts it on the setup screen; nobody can create email accounts or domains
on a Community server until the current version has been accepted. When the policies change, bump
VERSION and add the new file: the admin console then asks for acceptance again before more
accounts or domains can be created.
"""

VERSION = "1.0"
TITLE = "Zoltis Mail Community Edition policies"
URL = f"/legal/community-policies-v{VERSION}.md"
TERMS_URL = "https://zoltismail.com/legal/terms"


def public() -> dict:
    return {"version": VERSION, "title": TITLE, "url": URL, "terms_url": TERMS_URL}
