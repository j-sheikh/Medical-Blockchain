# -*- coding: utf-8 -*-
"""
Created on Fri Oct 21 11:46:04 2022

@author: jannik sheikh
"""
import hashlib
from MerkleTree import MerkleTree

    
class Block():
    def __init__(self, data, previous_hash,  receiver, timestamp):


        if not isinstance(data, list):
            data = [data]
            
        if not isinstance(receiver, list):
            receiver = [receiver]

        self.Merkle_Tree = MerkleTree(data)
        self.header = {"hash": hashlib.sha256(), "previous_hash": previous_hash, 'merkle_root': self.Merkle_Tree.merkle_root, "nonce": 0, 
                        "receiver": receiver, "timestamp": timestamp}
        
        
        # self.body = {f'data_{receiver[i]}': data[i] for i in range(len(data))} if len(data) > 1 else {'data': data[0]}
        self.body = {f'data_{receiver[i]}': data[i] for i in range(len(data))} if len(data) > 1 else {'data': data[0]} if receiver[0] == 'ALL' else {f'data_{receiver[0]}': data[0]}
        
        

    
    def mine(self, difficulty):

        
        self.header["hash"].update(str(self).encode())
        while int(self.header["hash"].hexdigest(), 16) > 2**(256 - difficulty):
            self.header["nonce"] += 1
            self.header["hash"] = hashlib.sha256()
            self.header["hash"].update(str(self).encode())
            
     
    def __str__(self):
        return f'{self.header["previous_hash"].hexdigest()}{self.header["merkle_root"]}{self.header["nonce"]}'




