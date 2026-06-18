"""Disable post creation for pocas.cyber on the cloud workspace by stripping
create_post / create_post_public from every role that grants either.

  python3 block.py           # block (saves originals to /tmp/cloud_originals.json)
  python3 block.py restore   # restore from saved snapshot
"""
import json, sys, pathlib, requests

BASE = 'https://pocas142.cloud.mattermost.com'
ATOK = 'eapzno38n7nmmqcq7fc3qpd3bo'
SNAPSHOT = pathlib.Path('/tmp/cloud_originals.json')
H = {'Authorization': f'Bearer {ATOK}', 'Accept': 'application/json'}

ROLES = [
    ('system_user',           'create_post'),
    ('channel_user',          'create_post'),
    ('channel_admin',         'create_post'),
    ('team_user',             'create_post'),
    ('team_admin',            'create_post'),
    ('team_post_all',         'create_post'),
    ('team_post_all_public',  'create_post_public'),
    ('system_post_all',       'create_post'),
    ('system_post_all_public','create_post_public'),
]

def api(method, path, **kw):
    return requests.request(method, BASE + path, headers=H, timeout=20, **kw)

def block():
    snap = {}
    for name, _ in ROLES:
        if name in snap:
            continue
        r = api('GET', f'/api/v4/roles/name/{name}')
        if r.status_code == 200:
            snap[name] = r.json()
    SNAPSHOT.write_text(json.dumps(snap))
    for name, perm in ROLES:
        cur = snap.get(name)
        if not cur:
            continue
        new = [p for p in cur['permissions'] if p != perm]
        if new == cur['permissions']:
            continue
        cur['permissions'] = new
        r = api('PUT', f"/api/v4/roles/{cur['id']}/patch",
                json={'permissions': new})
        print(f"  drop {perm} from {name}: HTTP {r.status_code}")
    print('done. pocas.cyber should now get 403 from POST /api/v4/posts')

def restore():
    if not SNAPSHOT.exists():
        print('no snapshot at', SNAPSHOT)
        sys.exit(1)
    snap = json.loads(SNAPSHOT.read_text())
    seen = set()
    for name, _ in ROLES:
        if name in seen:
            continue
        seen.add(name)
        cur = snap.get(name)
        if not cur:
            continue
        r = api('PUT', f"/api/v4/roles/{cur['id']}/patch",
                json={'permissions': cur['permissions']})
        print(f"  restore {name}: HTTP {r.status_code}")
    SNAPSHOT.unlink(missing_ok=True)
    print('done.')

if __name__ == '__main__':
    (restore if len(sys.argv) > 1 and sys.argv[1] == 'restore' else block)()
