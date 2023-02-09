# -*- coding: utf-8 -*-
"""
Created on Fri Oct 21 12:13:02 2022

@author: Jannik Sheikh
"""
import hashlib
import time
from  Block import Block
from timer import RepeatedTimer
import rsa
import base64

class Chain():
    def __init__(self, difficulty, callback = None):
        self.difficulty = difficulty
        self.pool = []
        self.receiver_pool = []
        self.blocks = []
        self.pubkey = None
        # self.blockchain = []
        self.create_origin_block()
        
        self.message_callback = None
        self.my_data_callback = None
        self.status_callback  = None
        self.add_block_callback = None
        self.status_callback_added = None
               
        
    def set_add_block_callback(self, callback):
        self.add_block_callback = callback

    def set_satus_callback(self, callback):
        self.status_callback = callback
        
    def set_pubkey(self, pubkey):
        self.pubkey = pubkey
        
    def set_my_data_callback(self, callback):
        self.my_data_callback = callback         
        
    def set_message_callback(self, callback):
        self.message_callback = callback 
    
    def proof_of_work(self, block):
        hash = hashlib.sha256()
        hash.update(str(block).encode())
        return block.header["hash"] == hash.hexdigest() and int(hash.hexdigest(), 16) < 2**(256-self.difficulty) and block.header["previous_hash"] == self.blocks[-1].header["hash"]
        
        
    def add_to_chain(self, block):
        if self.proof_of_work(block):
                       

            # self.blockchain.append(block)
            self.blocks.append(block)
            
            if self.status_callback:
                message = f'\n{time.strftime("%Y-%m-%d %H:%M:%S UTC+0", time.gmtime(time.time()))}\tData added to chain.'
                self.status_callback(message)
                
            if self.add_block_callback:
                self.add_block_callback(block)
            
            #reset pools
            self.receiver_pool = []
            self.pool = []
            # print('DATA added to CHAIN!')
            # self.chain_changed

        else:
            if self.status_callback:
                message = f'\n{time.strftime("%Y-%m-%d %H:%M:%S UTC+0", time.gmtime(time.time()))}\tFailed to add data to chain. Reason: Proof of work not correct.'
                self.message_callback(message)
            # print('Proof of work not correct!')
            
            
    def check_block(self, block_index):
        block = self.chain[block_index]
        return block.check_merkle_root()
  
    def add_foreign_block(self, block):
        
        def is_key_string(string):
            # Check if the string starts with "KEY:"
            if string.startswith("KEY:"):
                return True
            return False
       
        recover_rec = []
        for rec in block['header']['receiver']:
            if is_key_string(rec):
                pubpem = rec.split('KEY:')[1]
                recover_rec(rsa.PublicKey.load_pkcs1(pubpem.encode()))
            else:
                recover_rec.append(rec)
       
        block['header']['receiver'] = recover_rec
        
                
        for rec, data in block['body'].items():  
            data = block['body'][rec]
            try:
                decoded_data = bytes.fromhex(data)
                block['body'][rec] = decoded_data
            except ValueError:
                block['body'][rec] = data
           
        
        recover_block = Block(block['header'], block['body'], recover = True)
        if(recover_block.header['hash'] != self.blocks[-1].header['hash']):
            if self.proof_of_work(recover_block):
                print("added")
                self.blocks.append(recover_block)
                if self.status_callback:
                    message = f'\n{time.strftime("%Y-%m-%d %H:%M:%S UTC+0", time.gmtime(time.time()))}\tForeign block is added.'
                    self.set_satus_callback(message)
            else:
                print('FOREIGN BLOCK PROOF OF WORK FAILED')
        else:
            print("DONT NEED TO ADD, HAVE IT")
    
    
    def match_receiver_data_length(self, receiver, length):  
            return [receiver] * length
    
    def add_receiver(self, receiver):
        receiver_set = set(self.receiver_pool)
        if not isinstance(receiver, list):
            receiver = [receiver]
    
        for rec in receiver:
            if rec in receiver_set:
                count = 2
                while f"{rec}_{count}" in receiver_set:
                    count += 1
                rec = f"{rec}_{count}"
            self.receiver_pool.append(rec)
            receiver_set.add(rec)
        

    def add_to_pool(self, data, receiver):

        if len(self.pool) == 0:
            global rt
            rt = RepeatedTimer(10, self.mine) #change to 600 -> 10min
            
            
        if len(receiver) == 1:   
            data = data[0]
            self.pool.append(data)
        
        else:    
            self.pool = self.pool + data
      
        # print(self.pool)
        self.add_receiver(receiver)
        
        message = f'\n{time.strftime("%Y-%m-%d %H:%M:%S UTC+0", time.gmtime(time.time()))}\tProcess started to add data to the chain. May take up to 10 minutes.'
        self.status_callback(message)
        
        if len(self.pool) == 4:
            self.mine
            
        
        
    def create_origin_block(self):
        h = hashlib.sha256()
        h.update(''.encode())
        
        origin = Block(data = "Origin", previous_hash = h.hexdigest(), receiver = 'ALL', timestamp=0)
        origin.mine(self.difficulty)
        
        
        self.blocks.append(origin)

    def display_chain(self):
        if self.message_callback:
            self.message_callback(self.blocks)



    def display_last_block(self):
        self.print_block(self.blocks[-1])


    def search_chain_for_data(self):
        # print("SEARCHING")
        # print(self.pubkey)
        blocks = []
        for _, block in enumerate(self.blocks):
            # print(block.header['receiver'])
            if f'{self.pubkey}' in block.header['receiver'] or 'ALL' in block.header['receiver']:
                if block not in blocks:
                    blocks.append(block)
        # print(len(blocks))
        if self.my_data_callback and blocks:

            self.my_data_callback(blocks)

    # def get_chain_data(self, idx):
    #     return self.blocks[idx]

    
    # def print_block(self, block):
    #     if self.message_callback:
    #         self.message_callback(block)
            
            # print("\n\n=============================")
            # print(f"Header:\t\t{block.header}")
            # print(f"Body:\t{block.body}")
            # print("\n\n=============================")


        
    def mine(self):
        
        #sanity check
        if len(self.pool) > 0:
            # print('\nMINE')
            # print("LEN POOL", len(self.pool))
            
            rt.stop()
            # print('repeater stopped')
            

            block = Block(self.pool, self.blocks[-1].header['hash'], self.receiver_pool, timestamp= time.strftime("%Y-%m-%d %H:%M:%S UTC+0", time.gmtime(time.time())))
            block.mine(self.difficulty)
            
            if block.Merkle_Tree.check_merkle_root:
                        
                self.add_to_chain(block)     
            
            else:
                if self.status_callback:
                    message = f'\n{time.strftime("%Y-%m-%d %H:%M:%S UTC+0", time.gmtime(time.time()))}\tFailed to add data to pool. Reason: Merkle root did not match.'
                    self.status_callback(message)
                # print('merkle_root failed.')        
            
            
        else:
            print('NOTHING TO MINE')
