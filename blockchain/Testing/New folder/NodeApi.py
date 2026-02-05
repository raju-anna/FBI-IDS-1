
from flask import Flask, request, jsonify

class NodeAPI:
    def __init__(self, pbft_node):
        self.pbft = pbft_node
        self.app = Flask(__name__)
        self._register_routes()


    def _register_routes(self):

        @self.app.route("/health", methods=["GET"])
        def health():
            return jsonify({"status": "ok"}), 200

        @self.app.route("/pbft", methods=["POST"])
        def receive_pbft():
            msg = request.json

            if not msg or "Type" not in msg:
                return jsonify({"error": "Invalid PBFT message"}), 400

            self.pbft.On_Message_Received_From_Network(msg)
            return jsonify({"status": "received"}), 200

    def start(self, port):
        print(f"[NodeAPI] Listening on port {port}")
        self.app.run(host="0.0.0.0", port=port, threaded=True)
