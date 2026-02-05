
import requests

class PeerClient:
    def __init__(self, peers):
        """
        peers: dict {node_id: base_url}
        """
        self.peers = peers

    def send(self, node_id, msg):
        try:
            requests.post(
                f"{self.peers[node_id]}/pbft",
                json=msg,
                timeout=2
            )
        except requests.RequestException:
            pass

    def broadcast(self, msg):
        for node_id in self.peers:
            self.send(node_id, msg)
