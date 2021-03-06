# -*- coding: utf-8 -*-
"""
Created on Sat Jun  6 01:04:47 2020

@author: Vibhor
"""

import datetime
import hashlib
import json
from flask import Flask,jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse
#building a blockchain
class Blockchain:
    
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof = 1,prev_hash='0')#after mining we get proof
        self.nodes = set()
        
    def create_block(self, proof, prev_hash):
        block = {'index' :len(self.chain)+1,
                 'timestamp':str(datetime.datetime.now()),
                 'proof':proof,
                 'previous_hash':prev_hash,
                 'transactions':self.transactions}
        self.transactions =[]
        self.chain.append(block)
        return block
    
    def get_lastBlock(self):
        return self.chain[-1]
    
    def proof_of_work(self, prev_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - prev_proof**2).encode()).hexdigest()
            if hash_operation[:4] =='0000':
                check_proof = True
            else:
                new_proof+=1
            
        return new_proof
    
    def hash(self, block):
        encoded_block = json.dumps(block,sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    def is_chainValid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True
    
    def add_transaction(self,sender,receiver,amount):
        self.transactions.append({'sender':sender,
                                  'receiver':receiver,
                                  'amount':amount})
            
        previous_block = self.get_lastBlock()
        return previous_block['index']+1
    
    def add_node(self,address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
        
        
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')#looping over all nodes
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chainValid(chain):#finding max xhain
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False
#mining our blockchain
        
#create a web app

app = Flask(__name__)

node_address = str(uuid4()).replace('-','')

blockchain = Blockchain()

@app.route('/mine_block' ,methods=['GET'])
def mine_block():
    previous_block = blockchain.get_lastBlock()
    previous_proof =  previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    blockchain.add_transaction(sender = node_address,receiver = '5001',amount =1 )#coins after getting mined
    block = blockchain.create_block(proof,previous_hash)
    response = {'message':'Block Mined',
                'index':block['index'],
                'timestamp':block['timestamp'],
                'proof':block['proof'],
                'previous_hash':block['previous_hash'],
                'transactions':block['transactions']}  
    
    return jsonify(response),200



#getting full blockchain
@app.route('/get_chain' ,methods=['GET'])
def get_chain():
    response = {'chain' : blockchain.chain,
              'length': len(blockchain.chain)}
    return jsonify(response),200



@app.route('/add_transaction' ,methods=['POST'])
def add_transaction():#taken from postman
    json = request.get_json()
    transaction_keys = ['sender','receiver','amount']
    if not all(key in json for key in transaction_keys):
        return 'Elements missing',400
    index = blockchain.add_transaction(json['sender'],json['receiver'],json['amount'])
    response = {'message':f'Transaction added to Block {index}'}
    return jsonify(response),201

@app.route('/connect_node' ,methods=['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "no nodes",400
    for node in nodes:
        blockchain.add_node(node)
    response = {'message':'Following Nodes',
                'total_nodes':list(blockchain.nodes)}
    return jsonify(response),201

@app.route('/replace_chain' ,methods=['GET'])
def replace_chain():
    is_valid = blockchain.replace_chain()
    if is_valid:
        response = {'message':'Chain Replaced'}
    else :
        response = {'message':'No changes'}
    return jsonify(response),200
#running the app
g=input("enter the ip address");
p=input("enetr the port no");

app.run(host = g,port = p)
