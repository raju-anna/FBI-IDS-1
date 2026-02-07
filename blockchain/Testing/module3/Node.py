from ecdsa import VerifyingKey, SECP256k1
import json
import threading, time, queue
from collections import defaultdict

from .PeerClient import PeerClient
from .NodeApi import NodeAPI
from module2.PBFT import PBFT_Node
from module1.CryptoUtils import CryptoUtils


class Node(PBFT_Node, CryptoUtils):

    def __init__(self, node_id, port, peers, total_nodes, F, blockchain):
        super().__init__(node_id, total_nodes, F)

        self.node_id = node_id
        self.blockchain = blockchain
        self.peer_client = PeerClient(peers)
        self.port = port

        self.api = NodeAPI(self)

        # ---------------- CRYPTO ----------------
        self.private_key, self.public_key = self.generate_keypair()
        self.node_address = self.public_key_to_address(self.public_key)

        self.dh_private_key, self.dh_public_key = self.generate_dh_keypair()

        self.peer_public_keys = {}
        self.peer_dh_keys = {}
        self.session_keys = {}
        self.is_secure = False

        self.alert_votes = defaultdict(dict)
        self.node_stats = defaultdict(lambda: {"correct": 0, "wrong": 0})
        self.alert_counter = 0
        self.WRITE_THRESHOLD = 5

        # async writer
        self.stats_queue = queue.Queue()
        threading.Thread(target=self._stats_writer, daemon=True).start()

    def get_identity(self):
        return {
            "node_id": self.node_id,
            "public_key": self.public_key.to_string().hex()
        }

    def get_dh_public(self):
        return {
            "node_id": self.node_id,
            "dh_public_key": self.dh_public_key.to_string().hex()
        }

    def register_peer_identity(self, peer_id, pubkey_hex):
        self.peer_public_keys[peer_id] = VerifyingKey.from_string(
            bytes.fromhex(pubkey_hex), curve=SECP256k1
        )

    def register_peer_dh(self, peer_id, dh_pub_hex):
        peer_dh_key = VerifyingKey.from_string(
            bytes.fromhex(dh_pub_hex), curve=SECP256k1
        )

        self.peer_dh_keys[peer_id] = peer_dh_key
        shared_secret = self.derive_shared_secret(self.dh_private_key, peer_dh_key)
        self.session_keys[peer_id] = self.derive_session_key(shared_secret)


    def Send_To_All_Nodes(self, msg):
        if not self.is_secure:
            return

        plaintext = json.dumps(msg).encode("utf-8")

        for peer_id in self.peer_client.peers:
            key = self.session_keys.get(peer_id)
            if not key:
                continue

            enc = self.encrypt_message(key, plaintext)
            signature = self.sign_data(enc["ciphertext"], self.private_key)

            wire_msg = {
                "sender": self.node_id,
                "enc": enc,
                "signature": signature.hex()
            }

            self.peer_client.send(peer_id, wire_msg)

    def On_Message_Received_From_Network(self, msg):

        sender = msg.get("sender")
        enc = msg.get("enc")
        signature = bytes.fromhex(msg.get("signature", ""))

        if sender not in self.session_keys:
            return

        peer_pub = self.peer_public_keys.get(sender)
        if not peer_pub:
            return

        if not self.verify_signature(enc["ciphertext"], signature, peer_pub):
            return

        key = self.session_keys[sender]
        plaintext = self.decrypt_message(key, enc)

        pbft_msg = json.loads(plaintext.decode("utf-8"))
        print(f"[Node {self.node_id}] Decrypted:", pbft_msg)

        # record votes
        if pbft_msg.get("Type") == "PREPARE":
            bh = pbft_msg.get("Block_Hash")
            voter = pbft_msg.get("Sender")
            if bh and voter is not None:
                self.alert_votes[bh][voter] = True

        response = self.Receive(pbft_msg)

        if response:
            if response["Type"] == "DECIDED":
                self.On_Block_Committed(response["Seq"], response["Block_Hash"])
            else:
                self.Send_To_All_Nodes(response)

    def On_Block_Committed(self, seq, block_hash):
        block = self.Block_Pool.get(block_hash)
        if block:
            self.blockchain.add_block(block)

        votes = self.alert_votes.get(block_hash, {})
        if votes:
            true_votes = sum(votes.values())
            false_votes = len(votes) - true_votes
            majority = true_votes > false_votes

            for node, vote in votes.items():
                if vote == majority:
                    self.node_stats[node]["correct"] += 1
                else:
                    self.node_stats[node]["wrong"] += 1

            self.alert_counter += 1

            if self.alert_counter >= self.WRITE_THRESHOLD:
                self.stats_queue.put(dict(self.node_stats))
                self.alert_counter = 0

    def _stats_writer(self):
        while True:
            data = self.stats_queue.get()
            with open("validator_stats.json", "w") as f:
                json.dump(data, f, indent=2)
            print("📁 Validator stats written")


    def start(self):

        for peer_id in self.peer_client.peers:
            ident = self.peer_client.fetch_identity(peer_id)
            if ident:
                self.register_peer_identity(
                    ident["node_id"],
                    ident["public_key"]
                )


        for peer_id in self.peer_client.peers:
            resp = self.peer_client.send_dh_key(peer_id, self.get_dh_public())
            if resp:
                self.register_peer_dh(
                    resp["node_id"],
                    resp["dh_public_key"]
                )

        self.is_secure = True
        print(f"[Node {self.node_id}] Secure channels established")


        def delayed_test():
            time.sleep(3)
            if self.node_id == 0:
                self.Send_To_All_Nodes({
                    "Type": "TEST",
                    "data": "hello from node0"
                })

        threading.Thread(target=delayed_test, daemon=True).start()

        self.api.start(self.port)
