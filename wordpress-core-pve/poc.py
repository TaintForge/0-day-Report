#!/usr/bin/env python3
import argparse
import secrets
import string
import sys
import xmlrpc.client

import requests

def fail(message):
    print(f"FAIL: {message}")
    sys.exit(1)

def xmlrpc_call(base, method, params):
    body = xmlrpc.client.dumps(tuple(params), methodname=method, allow_none=True)
    response = requests.post(f"{base}/xmlrpc.php", data=body, headers={"Content-Type": "text/xml"}, timeout=20)
    response.raise_for_status()
    try:
        parsed, _ = xmlrpc.client.loads(response.text)
        return parsed[0] if len(parsed) == 1 else parsed
    except xmlrpc.client.Fault as fault:
        return fault

def expect_fault(result, code, text):
    if not isinstance(result, xmlrpc.client.Fault):
        fail(f"expected XML-RPC fault {code} containing {text!r}, got success: {result!r}")
    if result.faultCode != code or text not in result.faultString:
        fail(f"unexpected XML-RPC fault: code={result.faultCode} string={result.faultString!r}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Base URL of the WordPress site")
    parser.add_argument("--id", required=True, help="Username of a Contributor-role account")
    parser.add_argument("--pw", required=True, help="Password for that account")
    args = parser.parse_args()

    base = args.url.rstrip("/")
    user = args.id
    pw = args.pw

    marker = "blogger-publish-" + "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))

    draft_id = xmlrpc_call(
        base,
        "wp.newPost",
        [1, user, pw, {"post_type": "post", "post_status": "draft", "post_title": f"tf-draft-{marker}", "post_content": "draft body"}],
    )
    if isinstance(draft_id, xmlrpc.client.Fault):
        fail(f"wp.newPost draft unexpectedly faulted: {draft_id.faultCode} {draft_id.faultString}")
    draft_id = int(draft_id)

    wp_edit = xmlrpc_call(base, "wp.editPost", [1, user, pw, draft_id, {"post_status": "publish"}])
    expect_fault(wp_edit, 401, "publish posts")

    mt_publish = xmlrpc_call(base, "mt.publishPost", [draft_id, user, pw])
    expect_fault(mt_publish, 401, "publish this post")

    published_title = f"tf-published-{marker}"
    blogger_content = f"<title>{published_title}</title>published via blogger.editPost"
    blogger_result = xmlrpc_call(base, "blogger.editPost", ["app", str(draft_id), user, pw, blogger_content, True])
    if blogger_result is not True:
        fail(f"blogger.editPost did not return success: {blogger_result!r}")

    anon = requests.get(f"{base}/?p={draft_id}", allow_redirects=True, timeout=15)
    if anon.status_code != 200 or published_title not in anon.text:
        fail(f"anonymous fetch did not expose the published post: status={anon.status_code}")

    print("PASS")
    print(f"contributor={user}")
    print(f"post_id={draft_id}")
    print(f"published_title={published_title}")
    print(f"anon_status={anon.status_code}")
    print(f"public_url={base}/?p={draft_id}")

if __name__ == "__main__":
    main()
