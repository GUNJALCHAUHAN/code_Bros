import pymongo
from datetime import datetime
import hashlib
import json
import uuid


class Blockchain:
    def __init__(self) -> None:
        self.chain = None
        self.client = pymongo.MongoClient("mongodb://localhost:27017")
        self.db = self.client["blockchain"]
        self.blocksCollection = self.db["blocks"]
        self.transactionsCollection = self.db["transactions"]
        self.pending_transactions = []
        self.load_blocks_from_db()
        self.MAX_TRANSACTIONS_PER_BLOCK = 2

    def load_blocks_from_db(self):
        self.chain = []
        for block in self.blocksCollection.find().sort("index", pymongo.ASCENDING):
            self.chain.append(block)
        if not self.chain:
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = {
            'index': 1,
            'timestamp': str(datetime.now()),
            'transactions': [],
            'nonce': 100,
            'hash': '0',
            'previous_block_hash': '0'
        }
        self.blocksCollection.insert_one(genesis_block)
        self.chain.append(genesis_block)

    def create_new_block(self, nonce: int, previous_block_hash: str, hash: str):
        new_block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.now()),
            'transactions': self.pending_transactions,
            'nonce': nonce,
            'hash': hash,
            'previous_block_hash': previous_block_hash
        }
        self.blocksCollection.insert_one(new_block)  # Insert new block into MongoDB
        self.chain.append(new_block)  # Add new block to in-memory chain
        return new_block

    def get_transaction_by_id(self, transaction_id):
        return self.transactionsCollection.find_one({'transaction_id': transaction_id})

    def get_last_block(self):
        if self.chain:
            return self.chain[-1]
        else:
            return None

    def create_new_transaction(self, name: str, email: str, college: str,
                               course: str, roll_no: str):
        new_transaction = {
            'name': name,
            'email': email,
            'college': college,
            'course': course,
            'roll_no': roll_no,
            'transaction_id': str(uuid.uuid4())
        }
        inserted_id = self.transactionsCollection.insert_one(new_transaction).inserted_id
        return self.transactionsCollection.find_one({'_id': inserted_id})

    def add_transaction_to_pending_transactions(self, transaction_obj_id):
        self.pending_transactions.append(transaction_obj_id)
        if len(self.pending_transactions) >= self.MAX_TRANSACTIONS_PER_BLOCK:
            pending_transaction_objs = [self.get_transaction_by_id(transaction_id) for transaction_id in self.pending_transactions]
            nonce = self.proof_of_work(self.get_last_block()['hash'], pending_transaction_objs)
            self.create_new_block(nonce, self.get_last_block()['hash'], self.hash_block(self.get_last_block()['hash'], pending_transaction_objs, 100))
            self.pending_transactions = []
        return self.get_last_block()['index'] + 1

    def hash_block(self, previous_block_hash, current_block_data, nonce) -> str:
        data_as_string = previous_block_hash + str(nonce) + json.dumps(current_block_data)
        hash = hashlib.sha512(data_as_string.encode())
        return hash.hexdigest()

    def proof_of_work(self, previous_block_hash: str, current_block_data) -> int:
        nonce = 0
        hash = self.hash_block(previous_block_hash, current_block_data, nonce)
        while not str(hash).startswith('0000'):
            nonce += 1
            hash = self.hash_block(previous_block_hash, current_block_data, nonce)
        return nonce

    def chain_is_valid(self) -> bool:
        valid_chain = True
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            prev_block = self.chain[i - 1]
            block_hash = self.hash_block(prev_block['hash'], {
                'transactions': current_block['transactions'],
                'index': current_block['index']},
                current_block['nonce'])
            if not block_hash.startswith('0000'):
                valid_chain = False
            if current_block['previous_block_hash'] != prev_block['hash']:
                valid_chain = False
        genesis_block = self.chain[0]
        correct_nonce = genesis_block['nonce'] == 100
        correct_previous_block_hash = genesis_block['previous_block_hash'] == '0'
        correct_hash = genesis_block['hash'] == '0'
        correct_transactions = len(genesis_block['transactions']) == 0
        if not correct_nonce or not correct_previous_block_hash or not correct_hash or not correct_transactions:
            valid_chain = False
        return valid_chain

