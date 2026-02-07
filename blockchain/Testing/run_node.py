# run_node.py
import sys
from module3.Node import Node
from module3.config import get_config
from module1.BlockChain import IDSBlockchain
from module2.PBFT import PBFT_Node

print(">>> run_node.py started")


node_id = int(sys.argv[1])
config = get_config(node_id)

total_nodes = len(config["peers"]) + 1

blockchain = IDSBlockchain()

node = Node(
    node_id=node_id,
    port=config["port"],
    peers=config["peers"],
    total_nodes=total_nodes,
    F = 1,

    blockchain=blockchain
)

node.start()
