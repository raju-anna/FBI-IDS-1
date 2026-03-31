# module3/config.py  — Docker-aware version
#
# In Docker, "localhost" doesn't work between containers.
# Peer URLs are injected as environment variables by docker-compose:
#   PEER_0_URL=http://blockchain-node-0:5000
#   PEER_1_URL=http://blockchain-node-1:5001
#   etc.
#
# Falls back to localhost:500X for plain local development (no Docker).

import os

_DEFAULT_PEERS = {
    0: "http://localhost:5000",
    1: "http://localhost:5001",
    2: "http://localhost:5002",
    3: "http://localhost:5003",
}

def _peer_url(peer_id: int) -> str:
    env_key = f"PEER_{peer_id}_URL"
    return os.environ.get(env_key, _DEFAULT_PEERS[peer_id])

def get_config(node_id: int) -> dict:
    all_ids = list(_DEFAULT_PEERS.keys())
    peers = {
        pid: _peer_url(pid)
        for pid in all_ids
        if pid != node_id
    }
    base_port = int(os.environ.get("BASE_PORT", 5000))
    return {
        "port":  base_port + node_id,
        "peers": peers,
    }
