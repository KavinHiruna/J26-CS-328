"""Small helpers every page may use to call the components' services (agreed in docs/interfaces.md)."""
import json
import urllib.request

C3_URL = "http://127.0.0.1:8765"


def get_json(url, timeout=2):
    return json.loads(urllib.request.urlopen(url, timeout=timeout).read())
