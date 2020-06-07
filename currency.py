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
from Crypto.PublicKey import ECC
from Crypto.Hash import keccak
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import base64
from os import path
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
    
    def check_master(self,Category,Master,GroupId,ObjectId):
        #previous_block = chain[0]
        valid=True
        print(self.transactions)
        block_index = 1
        while block_index < len(self.chain) :
            block = self.chain[block_index]
            block_transactions= block["transactions"]
            follows=[following["Category"] for following in block_transactions]
            if 'Follower' != follows[block_index-1]:
                temp=[]
                temp.append(block_transactions[block_index-1])
                trans=[transacted["Master"] for transacted in temp]
                Gid=[groupID["GroupId"] for groupID in temp]
                Oid=[objectID["ObjectId"] for objectID in temp]
                if((Master  in trans) or (GroupId in Gid) or (ObjectId in Oid) ):
                    valid=False
                    return valid
                temp=[]
            block_index+=1
         
            
        follows=[following["Category"] for following in self.transactions]
        index=0
        while index < len(self.transactions):
            if 'Follower' != follows[index]:
                    temp=[]
                    temp.append(self.transactions[index])
                    trans=[transacted["Master"] for transacted in temp]
                    Gid=[groupID["GroupId"] for groupID in temp]
                    Oid=[objectID["ObjectId"] for objectID in temp]
                    if((Master  in trans) or (GroupId in Gid) or (ObjectId in Oid)):
                        valid=False
                        return valid
                    temp=[]
            index+=1
        return valid
    
    def check_follower(self,Category,Follower,GroupId,ObjectId,PubAddr,Signature):
        #previous_block = chain[0]
        valid=True
        print(self.transactions)
        block_index = 1
        while block_index < len(self.chain) :
            block = self.chain[block_index]
            block_transactions= block["transactions"]
            follows=[following["Category"] for following in block_transactions]
            if 'Master' != follows[block_index-1]:
                temp=[]
                temp.append(block_transactions[block_index-1])
                trans=[transacted["Follower"] for transacted in temp]
                Gid=[groupID["GroupId"] for groupID in temp]
                Oid=[objectID["ObjectId"] for objectID in temp]
                pAddr=[pubADDR["PubAddr"] for pubADDR in temp]
                sign=[SIGN["Signature"] for SIGN in temp ]
                if((Follower  in trans) or (GroupId in Gid) or (ObjectId in Oid) or (PubAddr in pAddr) or (Signature in sign)):
                    valid=False
                    return valid
                temp=[]
            block_index+=1
         
            
        follows=[following["Category"] for following in self.transactions]
        index=0
        while index < len(self.transactions):
            if 'Master' != follows[index]:
                    temp=[]
                    temp.append(self.transactions[index])
                    trans=[transacted["Follower"] for transacted in temp]
                    Gid=[groupID["GroupId"] for groupID in temp]
                    Oid=[objectID["ObjectId"] for objectID in temp]
                    pAddr=[pubADDR["PubAddr"] for pubADDR in temp]
                    sign=[SIGN["Signature"] for SIGN in temp ]
                    if((Follower  in trans) or (GroupId in Gid) or (ObjectId in Oid) or (PubAddr in pAddr) or (Signature in sign)):
                        valid=False
                        return valid
                    temp=[]
            index+=1
        return valid
            
    def check_message(self,Category,GroupId,Sender,Receiver):
        valid=True
        
        block_index = 1
        while block_index < len(self.chain) :
            block = self.chain[block_index]
            block_transactions= block["transactions"]
            follows=[following["GroupId"] for following in block_transactions]
            print(follows)
            print("bc")
            if GroupId in follows:
                return valid
            block_index+=1
        return False 
            
        follows=[following["GroupId"] for following in self.transactions]
        print(follows)
        print("transaction")
        if GroupId in follows:
            return valid
        return False
        
    def add_transaction_master(self,Category,Master,GroupId,ObjectId):
        self.transactions.append({'Category':Category,
                                  'Master':Master,
                                  'GroupId':GroupId,
                                  'ObjectId':ObjectId})
            
        previous_block = self.get_lastBlock()
        return previous_block['index']+1
        
    def add_transaction_follower(self,Category,Follower,GroupId,ObjectId,PubAddr,Signature):
        self.transactions.append({'Category':Category,
                                  'Follower':Follower,
                                  'GroupId':GroupId,
                                  'ObjectId':ObjectId,
                                  'PubAddr':PubAddr,
                                  'Signature':Signature})
          
        previous_block = self.get_lastBlock()
        return previous_block['index']+1
    
    def add_transaction_message(self,Category,GroupId,Sender,Receiver):
        self.transactions.append({'Category':Category,
                                 'GroupId':GroupId,
                                 'Sender':Sender,
                                 'Receiver':Receiver
                                 })
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
    
    
    def generatekey(self,groupid,x):
        key = ECC.generate(curve='P-256')
        pkey=key.public_key()
        fa=""+groupid+'.pem'
        fap="p"+groupid+'.pem'
        if(x==True):
            f=open(fa,'wt')
            f.write(key.export_key(format='PEM'))
            f.close()
            f=open(fap,'wt')
            f.write(pkey.export_key(format='PEM'))
            f.close()
    	#f = open('myprivatekey.pem','rt')
    	#key = ECC.import_key(f.read())
        return key.export_key(format='PEM'),pkey.export_key(format='PEM')

    def generateticket(self,objectid,groupid,pubaddr):
        #print(pubaddr)
        signmsg=objectid+groupid+pubaddr
    	#h=keccak.new(digest_bits=512)
    	#h.update(str.encode(signmsg))
        h=SHA256.new(str.encode(signmsg))
        key = ECC.import_key(open(groupid+'.pem','rt').read())
        signer=DSS.new(key,'fips-186-3')
        signature=signer.sign(h)
        #signature_enc = str(base64.b64encode(signature))
        #return signature_enc
        return base64.b64encode(signature)
    def verifyticket(self,groupid,objectid,pubaddr,sign):
        sign= base64.b64decode(sign)
        signmsg=objectid+groupid+pubaddr
        #h=keccak.new(digest_bits=512)
        #h.update(str.encode(signmsg))
        h=SHA256.new(str.encode(signmsg))
        key = ECC.import_key(open("p"+groupid+'.pem','rt').read())
        verifier=DSS.new(key,'fips-186-3')
        try:
            verifier.verify(h, sign)
            return True
        except ValueError:
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
    #blockchain.add_transaction(sender = node_address,receiver = 'vibhor',amount =1 )#coins after getting mined
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
    transaction_keys_message = ['Category','GroupId','Sender','Receiver']
    transaction_keys_master = ['Category','Master','GroupId','ObjectId']
    transaction_keys_follower = ['Category','Follower','GroupId','ObjectId','PubAddr','Signature']
    if not all(key in json for key in transaction_keys_master):
        if not all(key in json for key in transaction_keys_follower):
            if not all(key in json for key in transaction_keys_message):
                return 'Elements missing',400 
    if all(key in json for key in transaction_keys_master):
        valid=blockchain.check_master(json['Category'],json['Master'],json['GroupId'],json['ObjectId'])
        if valid:
            index = blockchain.add_transaction_master(json['Category'],json['Master'],json['GroupId'],json['ObjectId'])
            key,pkey=blockchain.generatekey(json['GroupId'],True)
            x=json['GroupId']
            response = {"GroupId":x,
		'private key for master':key,
	'Public key for master':pkey}
            return jsonify(response),201
        else:
            response={'message':'Transaction already added to Block '}
            return jsonify(response),201
    if all(key in json for key in transaction_keys_follower):
        valid=blockchain.check_follower(json['Category'],json['Follower'],json['GroupId'],json['ObjectId'],json['PubAddr'],json['Signature'])
        #valid=True
        signed_check=blockchain.verifyticket(json['GroupId'],json['ObjectId'],json['PubAddr'],json['Signature'])
        #signed_check=True
        if not signed_check:
            response={'message':'Wrong Token '}
            return jsonify(response),201
        if valid and signed_check:
            index = blockchain.add_transaction_follower(json['Category'],json['Follower'],json['GroupId'],json['ObjectId'],json['PubAddr'],json['Signature'])
        else:
            response={'message':'Transaction already added to Block '}
            return jsonify(response),201
    if all(key in json for key in transaction_keys_message):
        valid=blockchain.check_message(json['Category'],json['GroupId'],json['Sender'],json['Receiver'])
        if valid:
            index = blockchain.add_transaction_message(json['Category'],json['GroupId'],json['Sender'],json['Receiver'])
        else:
            response={'message':'GroupId does not exits you scammer '}
            return jsonify(response),201
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

@app.route('/generate_key' ,methods=['GET'])
def generate_key():
    key,pkey=blockchain.generatekey("",False)
    response = {"public key":key,
	'Private key':pkey}
    return jsonify(response),201



@app.route('/get_ticket' ,methods=['POST'])
def get_ticket():
    json = request.get_json()
    groupid = json.get('GroupId')
    objectid=json.get('ObjectId')
    pkey=json.get('Pubkey')
    if not path.exists(groupid+'.pem'):
        response={"":"group doesnt exists"}
        return jsonify(response),201
    signature=blockchain.generateticket(objectid,groupid,pkey)
   #x=[]
    #x.append(signature)
    response = {"GroupId":groupid,
		"ObjectId":objectid,
		"pubaddr":pkey,
		"signature":signature}
    return jsonify(response),201
#running the app
app.run(host = '0.0.0.0',port = 5000)
