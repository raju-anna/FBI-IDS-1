# run_node.py
import sys
from module3.Node import Node
from module3.config import get_config
from module1.BlockChain import IDSBlockchain
from module2.PBFT import PBFT_Node

print(">>> run_node.py started")


node_id = int(sys.argv[1])
config = get_config(node_id)

blockchain = IDSBlockchain()

pbft = PBFT_Node(
    Node_Id=node_id,
    Total_Nodes=4,
    F=1,
    ids_model=lambda alert: True  # dummy IDS
)

node = Node(
    node_id=node_id,
    port=config["port"],
    peers=config["peers"],
    blockchain=blockchain,
    pbft_node=pbft
)

node.start()
