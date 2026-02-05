from .PeerClient import PeerClient
from .NodeApi import NodeAPI


class Node:
    def __init__(self, node_id, port, peers,
                 blockchain, pbft_node):

        """
        node_id    : int (0 .. N-1)
        peers      : dict {node_id: url}
        """
        self.node_id = node_id
        self.blockchain = blockchain
        self.pbft = pbft_node
        self.peer_client = PeerClient(peers)
        self.port = port

        self.pbft.Send_To_All_Nodes = self._send_to_all
        self.pbft.On_Message_Received_From_Network = self._on_message
        self.pbft.On_Block_Committed = self._on_block_committed

        self.api = NodeAPI(self.pbft)

    def _send_to_all(self, msg):
        print(f"[Node {self.node_id}] Broadcasting {msg['Type']}")
        self.peer_client.broadcast(msg)

    def _on_message(self, msg):
        """
        Called by NodeAPI when a message arrives.
        """

        print(f"[Node {self.node_id}] Received message: {msg}")

        response = self.pbft.Receive(msg)

        if response:
            if response["Type"] == "DECIDED":
                self.pbft.On_Block_Committed(
                    response["Seq"],
                    response["Block_Hash"]
                )
            else:
                self.pbft.Send_To_All_Nodes(response)

    def _on_block_committed(self, seq, block_hash):
        """
        Final PBFT decision → blockchain commit
        """
        block = self.pbft.Block_Pool.get(block_hash)

        if block is None:
            print(f"[Node {self.node_id}] Block missing for commit")
            return

        success = self.blockchain.add_block(block)

        if success:
            print(f"[Node {self.node_id}] Block committed (seq={seq})")
        else:
            print(f"[Node {self.node_id}] Block rejected by blockchain")

    def test_pbft_propose(self):
    # Only leader proposes
        if self.pbft.Get_Current_Leader() != self.node_id:
            return

        print(f"[Node {self.node_id}] 🚀 Triggering PBFT proposal")

        dummy_block1 = {
            "block_id": "block-1",
            "data": "pbft-test1",
            "block_hash": "fgsrdtfuytyg457fg7it7edg7@79i0hu"

        }

        dummy_block2 = {
            "block_id": "block-2",
            "data": "pbft-test2",
            "block_hash": "fgsrdtfewygfefe8rvyhg488e90fueifn9i0hu"

        }



        msg = self.pbft.Propose(dummy_block1)
        self.pbft.Send_To_All_Nodes(msg)

        # msg = self.pbft.Propose(dummy_block2)
        # self.pbft.Send_To_All_Nodes(msg)



    # def start(self):
    #     print(">>> Node.start() called")
    #     print(
    #         f"[Node {self.node_id}] Starting | "
    #         f"Leader = {self.pbft.Get_Current_Leader()} | "
    #         f"Port = {self.port}"
    #     )
    #     self.api.start(self.port)

    def start(self):
        print(f"[Node {self.node_id}] Starting | Port = {self.port}")

        import threading, time
        def delayed_propose():
            time.sleep(15)
            self.test_pbft_propose()

        threading.Thread(target=delayed_propose).start()

        self.api.start(self.port)


