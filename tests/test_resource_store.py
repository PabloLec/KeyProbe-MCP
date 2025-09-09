# tests/test_resource_store.py
from keyprobe.resource_store import ResourceStore

def test_resource_store_ttl_and_purge():
    t = [0.0]
    def now():
        return t[0]

    store = ResourceStore(ttl_seconds=5, now_fn=now)
    rid = store.put({"hello": "world"}, tmp_path=None)

    # Immédiatement présent
    e = store.get(rid)
    assert e.summary["hello"] == "world"

    # Avance le temps au-delà du TTL
    t[0] = 10.0
    store.purge()
    try:
        store.get(rid)
        assert False, "Expected KeyError after expiration"
    except KeyError:
        pass
