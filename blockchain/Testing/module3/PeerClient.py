import requests


class PeerClient:
    def __init__(self, peers):
        """
        peers: dict {node_id: base_url}
        """
        self.peers = peers
        
    def fetch_identity(self, node_id):
        try:
            r = requests.get(
                f"{self.peers[node_id]}/identity",
                timeout=2
            )
            if r.status_code == 200:
                return r.json()
        except requests.RequestException:
            pass
        return None
    
    def send_dh_key(self, node_id, payload):
        """
        payload:
        {
            "node_id": int,
            "dh_public_key": hex
        }
        """
        try:
            r = requests.post(
                f"{self.peers[node_id]}/dh",
                json=payload,
                timeout=2
            )
            if r.status_code == 200:
                return r.json()
        except requests.RequestException:
            pass
        return None


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
