"""Post a message into town-square as pocas.cyber via the incoming webhook.
Works even while pocas.cyber is blocked from POST /api/v4/posts.

  python3 write.py                       # default text
  python3 write.py hi
"""
import sys, requests

HOOK = 'https://pocas142.cloud.mattermost.com/hooks/fspgo118p7bzbnu7ugg858435e'

msg = ' '.join(sys.argv[1:]) or 'hello from webhook'
r = requests.post(HOOK, json={'text': msg}, timeout=10)
print(f'{r.status_code} {r.text}')
