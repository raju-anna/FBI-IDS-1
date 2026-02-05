import hashlib
import json
import time
from typing import List, Dict, Any, Optional, Tuple
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from collections import defaultdict
import copy


class CryptoUtils:
    
    @staticmethod
    def sha256(data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    @staticmethod
    def generate_keypair() -> Tuple[SigningKey, VerifyingKey]:
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.get_verifying_key()
        return private_key, public_key
    
    @staticmethod
    def sign_data(data: str, private_key: SigningKey) -> bytes:
        return private_key.sign(data.encode('utf-8'))
    
    @staticmethod
    def verify_signature(data: str, signature: bytes, 
                        public_key: VerifyingKey) -> bool:
        try:
            public_key.verify(signature, data.encode('utf-8'))
            return True
        except BadSignatureError:
            return False
    
    @staticmethod
    def public_key_to_address(public_key: VerifyingKey) -> str:
        pubkey_bytes = public_key.to_string()
        hash_result = hashlib.sha256(pubkey_bytes).hexdigest()
        return '0x' + hash_result[-40:]


class MerkleTree:
    
    def __init__(self, transactions: List[Dict]):
        self.transactions = transactions
        self.leaves = [self._hash_transaction(tx) for tx in transactions]
        self.root = self._build_tree(self.leaves) if self.leaves else None
    
    def _hash_transaction(self, tx: Dict) -> str:
        tx_string = json.dumps(tx, sort_keys=True)
        return CryptoUtils.sha256(tx_string)
    
    def _build_tree(self, nodes: List[str]) -> str:
        if len(nodes) == 0:
            return None
        if len(nodes) == 1:
            return nodes[0]
        
        new_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            combined = left + right
            new_level.append(CryptoUtils.sha256(combined))
        
        return self._build_tree(new_level)
    
    def get_root(self) -> Optional[str]:
        return self.root
    
    def get_proof(self, tx_index: int) -> List[Tuple[str, str]]:
        if tx_index < 0 or tx_index >= len(self.leaves):
            return []
        
        proof = []
        nodes = self.leaves.copy()
        index = tx_index
        
        while len(nodes) > 1:
            if index % 2 == 0:
                sibling_index = index + 1 if index + 1 < len(nodes) else index
                sibling = nodes[sibling_index]
                position = 'right'
            else:
                sibling_index = index - 1
                sibling = nodes[sibling_index]
                position = 'left'
            
            proof.append((sibling, position))
            
            new_nodes = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
                new_nodes.append(CryptoUtils.sha256(left + right))
            
            nodes = new_nodes
            index = index // 2
        
        return proof
    
    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Tuple[str, str]], 
                    root: str) -> bool:
        current_hash = leaf_hash
        
        for sibling_hash, position in proof:
            if position == 'left':
                combined = sibling_hash + current_hash
            else:
                combined = current_hash + sibling_hash
            current_hash = CryptoUtils.sha256(combined)
        
        return current_hash == root


class AlertTransaction:
    
    def __init__(self, node_id: str, alert_type: str,
                 detector_outputs: Dict[str, float],
                 features_summary: Dict[str, Any],
                 timestamp: float = None):
        self.tx_id = None
        self.node_id = node_id
        self.alert_type = alert_type
        self.timestamp = timestamp or time.time()
        self.detector_outputs = detector_outputs
        self.features_summary = features_summary
        self.signature = None
        self.signer_address = None
    
    def to_dict(self, include_signature: bool = True) -> Dict:
        data = {
            'tx_id': self.tx_id,
            'node_id': self.node_id,
            'alert_type': self.alert_type,
            'timestamp': self.timestamp,
            'detector_outputs': self.detector_outputs,
            'features_summary': self.features_summary,
            'signer_address': self.signer_address
        }
        
        if include_signature and self.signature:
            data['signature'] = self.signature.hex()
        
        return data
    
    def get_signing_data(self) -> str:
        data = self.to_dict(include_signature=False)
        del data['tx_id']
        return json.dumps(data, sort_keys=True)
    
    def sign(self, private_key: SigningKey) -> None:
        signing_data = self.get_signing_data()
        self.signature = CryptoUtils.sign_data(signing_data, private_key)
        
        self.tx_id = CryptoUtils.sha256(signing_data + self.signature.hex())
        
        public_key = private_key.get_verifying_key()
        self.signer_address = CryptoUtils.public_key_to_address(public_key)
    
    def verify(self, public_key: VerifyingKey) -> bool:
        if not self.signature:
            return False
        
        signing_data = self.get_signing_data()
        return CryptoUtils.verify_signature(signing_data, self.signature, public_key)


class Block:
    
    def __init__(self, block_number: int, transactions: List[AlertTransaction],
                 previous_hash: str, view_number: int = 0,
                 sequence_number: int = 0, proposer_id: str = None,
                 timestamp: float = None):
        self.block_number = block_number
        self.timestamp = timestamp or time.time()
        self.previous_hash = previous_hash
        self.transactions = transactions
        
        self.view_number = view_number
        self.sequence_number = sequence_number
        self.proposer_id = proposer_id
        
        self.prepare_signatures = []
        self.commit_signatures = []
        
        tx_dicts = [tx.to_dict() for tx in transactions]
        self.merkle_tree = MerkleTree(tx_dicts)
        self.merkle_root = self.merkle_tree.get_root() or "0" * 64
        
        self.alert_count = len(transactions)
        self.severity_summary = self._calculate_severity_summary()
        
        self.block_hash = self.calculate_hash()
    
    def _calculate_severity_summary(self) -> Dict[str, int]:
        severity_map = {
            'recon': 'low',
            'port_scan': 'low',
            'brute_force': 'medium',
            'malware': 'medium',
            'privilege_escalation': 'high',
            'lateral_movement': 'high',
            'data_exfiltration': 'critical',
            'ransomware': 'critical',
            'DDoS': 'high',
            'SQLi': 'high'
        }
        
        summary = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for tx in self.transactions:
            severity = severity_map.get(tx.alert_type, 'medium')
            summary[severity] += 1
        
        return summary
    
    def calculate_hash(self) -> str:
        header_data = {
            'block_number': self.block_number,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'view_number': self.view_number,
            'sequence_number': self.sequence_number,
            'proposer_id': self.proposer_id,
            'alert_count': self.alert_count,
            'severity_summary': self.severity_summary
        }
        
        header_string = json.dumps(header_data, sort_keys=True)
        return CryptoUtils.sha256(header_string)
    
    def add_prepare_signature(self, validator_id: str, signature: bytes):
        self.prepare_signatures.append({
            'validator_id': validator_id,
            'signature': signature.hex()
        })
    
    def add_commit_signature(self, validator_id: str, signature: bytes):
        self.commit_signatures.append({
            'validator_id': validator_id,
            'signature': signature.hex()
        })
    
    def to_dict(self) -> Dict:
        return {
            'block_number': self.block_number,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'view_number': self.view_number,
            'sequence_number': self.sequence_number,
            'proposer_id': self.proposer_id,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'prepare_signatures': self.prepare_signatures,
            'commit_signatures': self.commit_signatures,
            'alert_count': self.alert_count,
            'severity_summary': self.severity_summary,
            'block_hash': self.block_hash
        }
    
    def verify_transaction_inclusion(self, tx_index: int) -> bool:
        if tx_index < 0 or tx_index >= len(self.transactions):
            return False
        
        tx = self.transactions[tx_index]
        leaf_hash = self.merkle_tree._hash_transaction(tx.to_dict())
        proof = self.merkle_tree.get_proof(tx_index)
        
        return MerkleTree.verify_proof(leaf_hash, proof, self.merkle_root)


class IDSBlockchain:
    
    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[AlertTransaction] = []
        self.validators: Dict[str, VerifyingKey] = {}
        self.current_view = 0
        self.current_sequence = 0
        
        self._create_genesis_block()
    
    def _create_genesis_block(self) -> None:
        genesis = Block(
            block_number=0,
            transactions=[],
            previous_hash="0" * 64,
            view_number=0,
            sequence_number=0,
            proposer_id="genesis"
        )
        self.chain.append(genesis)
    
    def register_validator(self, validator_id: str, public_key: VerifyingKey):
        self.validators[validator_id] = public_key
    
    def add_transaction(self, transaction: AlertTransaction) -> bool:
        self.pending_transactions.append(transaction)
        return True
    
    def create_block(self, proposer_id: str, max_transactions: int = 100) -> Block:
        if not self.pending_transactions:
            return None
        
        transactions = self.pending_transactions[:max_transactions]
        
        previous_block = self.chain[-1]
        new_block = Block(
            block_number=len(self.chain),
            transactions=transactions,
            previous_hash=previous_block.block_hash,
            view_number=self.current_view,
            sequence_number=self.current_sequence,
            proposer_id=proposer_id
        )
        
        self.current_sequence += 1
        return new_block
    
    def add_block(self, block: Block) -> bool:
        if block.block_number != len(self.chain):
            print(f"Invalid block number: {block.block_number}, expected {len(self.chain)}")
            return False
        
        if block.previous_hash != self.chain[-1].block_hash:
            print("Invalid previous hash")
            return False
        
        expected_hash = block.calculate_hash()
        if block.block_hash != expected_hash:
            print("Invalid block hash")
            return False
        
        self.chain.append(block)
        
        tx_ids = {tx.tx_id for tx in block.transactions}
        self.pending_transactions = [
            tx for tx in self.pending_transactions 
            if tx.tx_id not in tx_ids
        ]
        
        return True
    
    def validate_chain(self) -> bool:
        if len(self.chain) == 0:
            return False
        
        genesis = self.chain[0]
        if genesis.block_number != 0 or genesis.previous_hash != "0" * 64:
            return False
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            if current_block.block_number != i:
                return False
            
            if current_block.previous_hash != previous_block.block_hash:
                return False
            
            if current_block.block_hash != current_block.calculate_hash():
                return False
        
        return True
    
    def get_block(self, block_number: int) -> Optional[Block]:
        if 0 <= block_number < len(self.chain):
            return self.chain[block_number]
        return None
    
    def get_latest_block(self) -> Block:
        return self.chain[-1]
    
    def get_alerts_by_type(self, alert_type: str) -> List[AlertTransaction]:
        alerts = []
        for block in self.chain[1:]:
            for tx in block.transactions:
                if tx.alert_type == alert_type:
                    alerts.append(tx)
        return alerts
    
    def get_alerts_by_node(self, node_id: str) -> List[AlertTransaction]:
        alerts = []
        for block in self.chain[1:]:
            for tx in block.transactions:
                if tx.node_id == node_id:
                    alerts.append(tx)
        return alerts
    
    def get_statistics(self) -> Dict[str, Any]:
        total_alerts = sum(block.alert_count for block in self.chain[1:])
        
        severity_totals = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for block in self.chain[1:]:
            for severity in severity_totals:
                severity_totals[severity] += block.severity_summary[severity]
        
        return {
            'total_blocks': len(self.chain),
            'total_alerts': total_alerts,
            'pending_transactions': len(self.pending_transactions),
            'severity_summary': severity_totals,
            'chain_valid': self.validate_chain()
        }


