from collections import defaultdict

class PBFT_Node:
    """
    PBFT Node with:
    - Deterministic leader selection (view % N)
    - IDS-based verification in PRE-PREPARE
    - Network-safe message format
    """

    def __init__(self, Node_Id, Total_Nodes, F, ids_model=None):
        """
        Node_Id      : int (0 ... N-1)
        Total_Nodes  : int
        F            : max faulty nodes
        ids_model    : callable(alert_metadata) -> bool
        """
        self.Node_Id = Node_Id
        self.Total_Nodes = Total_Nodes
        self.F = F

        # PBFT state
        self.View = 0
        self.Seq = 0

        self.Pre_Prepare = {}                          # Seq -> {Block_Hash, Alert_Metadata}
        self.Prepare = defaultdict(lambda: defaultdict(set))  # Seq -> hash -> voters
        self.Commit = defaultdict(lambda: defaultdict(set))   # Seq -> hash -> voters
        self.Committed = {}                            # Seq -> Block_Hash

        # Local block storage (never sent over network)
        self.Block_Pool = {}                           # Block_Hash -> Block

        # IDS model
        self.ids_model = ids_model


    def Is_Primary_Node(self) -> bool:
        """
        Deterministic PBFT leader selection
        """
        return self.Node_Id == (self.View % self.Total_Nodes)

    def Get_Current_Leader(self) -> int:
        return self.View % self.Total_Nodes


    def Is_Valid_Alert(self, alert_metadata: dict) -> bool:
        """
        Run alert metadata on local IDS.
        Returns True if malicious.
        """
        if self.ids_model is None:
            return True 
        return self.ids_model(alert_metadata)


    def Propose(self, block):
        if not self.Is_Primary_Node():
            raise Exception("Only primary can propose")

        self.Seq += 1
        block_hash = block["block_hash"]

        self.Block_Pool[block_hash] = block

        # alert_metadata = [tx.to_dict() for tx in block.transactions]
        alert_metadata = "nhewufhewjfiufwe0fijfhrgofdknc"

        # Record pre-prepare locally
        self.Pre_Prepare[self.Seq] = {
            "Block_Hash": block_hash,
            "Alert_Metadata": alert_metadata
        }

        return {
            "Type": "PRE-PREPARE",
            "View": self.View,
            "Seq": self.Seq,
            "Block_Hash": block_hash,
            "Alert_Metadata": alert_metadata,
            "Sender": self.Node_Id
        }


    def On_Message_Received_From_Network(self, msg):
        response = self.Receive(msg)

        if response:
            if response["Type"] == "DECIDED":
                self.On_Block_Committed(
                    response["Seq"],
                    response["Block_Hash"]
                )
            else:
                self.Send_To_All_Nodes(response)


    def Receive(self, Msg):
        if Msg["View"] != self.View:
            return None

        if Msg["Type"] == "PRE-PREPARE":
            return self._On_Pre_Prepare(Msg)

        if Msg["Type"] == "PREPARE":
            return self._On_Prepare(Msg)

        if Msg["Type"] == "COMMIT":
            return self._On_Commit(Msg)

        return None

    def _On_Pre_Prepare(self, Msg):
        Seq = Msg["Seq"]
        block_hash = Msg["Block_Hash"]
        alert_metadata = Msg["Alert_Metadata"]

        if Seq in self.Pre_Prepare:
            return None

        if not self.Is_Valid_Alert(alert_metadata):
            return None

        self.Pre_Prepare[Seq] = {
            "Block_Hash": block_hash,
            "Alert_Metadata": alert_metadata
        }

        return {
            "Type": "PREPARE",
            "View": Msg["View"],
            "Seq": Seq,
            "Block_Hash": block_hash,
            "Sender": self.Node_Id
        }

    def _On_Prepare(self, Msg):
        Seq = Msg["Seq"]
        block_hash = Msg["Block_Hash"]
        sender = Msg["Sender"]

        # if Seq not in self.Pre_Prepare:
        #     return None

        self.Prepare[Seq][block_hash].add(sender)

        if len(self.Prepare[Seq][block_hash]) >= 2 * self.F + 1 and  Seq in self.Pre_Prepare:
            return {
                "Type": "COMMIT",
                "View": Msg["View"],
                "Seq": Seq,
                "Block_Hash": block_hash,
                "Sender": self.Node_Id
            }

        return None

    def _On_Commit(self, Msg):
        Seq = Msg["Seq"]
        block_hash = Msg["Block_Hash"]
        sender = Msg["Sender"]

        self.Commit[Seq][block_hash].add(sender)

        if len(self.Commit[Seq][block_hash]) >= 2 * self.F + 1:
            if Seq not in self.Committed:
                self.Committed[Seq] = block_hash
                return {
                    "Type": "DECIDED",
                    "Seq": Seq,
                    "Block_Hash": block_hash
                }

        return None

    def Send_To_All_Nodes(self, Msg):
        """
        Implemented by networking layer
        """
        pass

    def On_Block_Committed(self, Seq, Block_Hash):
        """
        Implemented by node controller
        """
        pass
