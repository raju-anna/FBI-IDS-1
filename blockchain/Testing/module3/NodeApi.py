from flask import Flask, request, jsonify


class NodeAPI:
    def __init__(self, node):
        """
        node: instance of Node (PBFT + Crypto wrapper)
        """
        self.node = node
        self.app = Flask(__name__)
        self._register_routes()

    def _register_routes(self):

        @self.app.route("/health", methods=["GET"])
        def health():
            return jsonify({"status": "ok"}), 200

        @self.app.route("/identity", methods=["GET"])
        def identity():
            return jsonify(self.node.get_identity()), 200

        @self.app.route("/dh", methods=["POST"])
        def dh_exchange():
            data = request.json
            if not data:
                return jsonify({"error": "Invalid DH payload"}), 400

            peer_id = data.get("node_id")
            peer_dh_key = data.get("dh_public_key")

            if peer_id is None or peer_dh_key is None:
                return jsonify({"error": "Missing DH fields"}), 400

            self.node.register_peer_dh(peer_id, peer_dh_key)

            return jsonify(self.node.get_dh_public()), 200

        @self.app.route("/pbft", methods=["POST"])
        def receive_pbft():
            msg = request.json

            if not msg or "enc" not in msg or "signature" not in msg:
                return jsonify({"error": "Encrypted PBFT required"}), 400

            self.node.On_Message_Received_From_Network(msg)
            return jsonify({"status": "received"}), 200

    def start(self, port):
        print(f"[NodeAPI] Listening on port {port}")
        self.app.run(host="0.0.0.0", port=port, threaded=True)
