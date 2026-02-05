class PBFT_Node:
    """
    This class represents A Node participating in the PBFT consensus mechanism.

    Parameters:
    Node_Id     -> int (Represents the Node's id)
    Total_Nodes -> int (Represents the total number of Nodes participating in the consensus)
    F           -> int (Represents the maximum faulty nodes)
    Is_Primary  -> bool (True if the Node is a Primary Node)
    """

    def __init__(self, Node_Id, Total_Nodes, F, Is_Primary=False):
        self.Node_Id = Node_Id
        self.Total_Nodes = Total_Nodes
        self.F = F
        self.Is_Primary = Is_Primary

        self.View = 0
        self.Seq = 0

        self.Pre_Prepare = {}     
        self.Prepare = {}       
        self.Commit = {}       
        self.Committed = {}       

    def Propose(self, Block_Hash):
        if not self.Is_Primary:
            raise Exception("Only primary can propose")

        self.Sequence += 1

        return {
            "Type": "PRE-PREPARE",
            "View": self.View,
            "Seq": self.Seq,
            "Value": Block_Hash,
            "Sender": self.Node_Id
        }

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
        Value = Msg["Value"]

        if Seq in self.Pre_Prepare:
            return None

        self.Pre_Prepare[Seq] = Value

        return {
            "Type": "PREPARE",
            "View": Msg["View"],
            "Seq": Seq,
            "Value": Value,
            "Sender": self.Node_Id
        }

    def _On_Prepare(self, Msg):
        Seq = Msg["Seq"]
        Value = Msg["Value"]
        Sender = Msg["Sender"]

        if Seq not in self.Pre_Prepare:
            return None

        if self.Pre_Prepare[Seq] != Value:
            return None

        if Seq not in self.Prepare:
            self.Prepare[Seq] = {}
        if Value not in self.Prepare[Seq]:
            self.Prepare[Seq][Value] = set()

        self.Prepare[Seq][Value].add(Sender)

        if len(self.Prepare[Seq][Value]) >= 2 * self.F + 1:
            return {
                "Type": "COMMIT",
                "View": Msg["View"],
                "Seq": Seq,
                "Value": Value,
                "Sender": self.Node_Id
            }

        return None

    def _On_Commit(self, Msg):
        Seq = Msg["Seq"]
        Value = Msg["Value"]
        Sender = Msg["Sender"]

        if Seq not in self.Commit:
            self.Commit[Seq] = {}
        if Value not in self.Commit[Seq]:
            self.Commit[Seq][Value] = set()

        self.Commit[Seq][Value].add(Sender)

        if len(self.Commit[Seq][Value]) >= 2 * self.F + 1:
            if Seq not in self.Committed:
                self.Committed[Seq] = Value
                return {
                    "Type": "DECIDED",
                    "Seq": Seq,
                    "Value": Value
                }

        return None
