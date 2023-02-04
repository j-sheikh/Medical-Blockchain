# -*- coding: utf-8 -*-
"""
Created on Fri Oct 21 12:13:02 2022

@author: hikth
"""
import hashlib
import time
from  Block import Block
from timer import RepeatedTimer

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
        
    def set_pubkey(self, pubkey):
        self.pubkey = pubkey
        
    def set_my_data_callback(self, callback):
        self.my_data_callback = callback
        
    def set_message_callback(self, callback):
        self.message_callback = callback 
    
    def proof_of_work(self, block):
        hash = hashlib.sha256()
        hash.update(str(block).encode())
        return block.header["hash"].hexdigest() == hash.hexdigest() and int(hash.hexdigest(), 16) < 2**(256-self.difficulty) and block.header["previous_hash"] == self.blocks[-1].header["hash"]
        
        
        
    def add_to_chain(self, block):
        if self.proof_of_work(block):
                       

            # self.blockchain.append(block)
            self.blocks.append(block)
            
            #reset pools
            self.receiver_pool = []
            self.pool = []
            print('DATA added to CHAIN!')
            # self.chain_changed

        else:
            print('Proof of work not correct!')
            
            
    def check_block(self, block_index):
        block = self.chain[block_index]
        return block.check_merkle_root()
  
    # def add_foreign_Block(self, dict):
    #     self.blockchain.append(dict)
    
    
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
        # time.sleep(1)
        
        #first time calling add_to_pool init rt
        # print(receiver)
        if len(self.pool) == 0:
            print('set repeater')
            global rt
            rt = RepeatedTimer(10, self.mine) #change to 600 -> 10min
                     
        self.pool.append(data)
        
        self.add_receiver(receiver)
        
        if len(self.pool) == 4:
            print("MORE THAN 4")
            self.mine
            
    def stop_repeater(self):
        rt.stop()
        print('REPEATER STOPPED!')

        
        
    def create_origin_block(self):
        h = hashlib.sha256()
        h.update(''.encode())
        
        origin = Block(data = "Origin", previous_hash = h, receiver = 'ALL', timestamp=0)
        origin.mine(self.difficulty)
        
        
        self.blocks.append(origin)

    def display_chain(self):
        if self.message_callback:
            self.message_callback(self.blocks)


    def display_last_block(self):
        self.print_block(self.blocks[-1])


    def search_chain_for_data(self):
        print("SEARCHING")
        print(self.pubkey)
        blocks = []
        for _, block in enumerate(self.blocks):
            print(block.header['receiver'])
            if self.pubkey in block.header['receiver'] or 'ALL' in block.header['receiver']:
                print(True)
                if block not in blocks:
                    blocks.append(block)
        print(len(blocks))
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
            print('\nMINE')
            print("LEN POOL", len(self.pool))
            
            rt.stop()
            print('repeater stopped')
            

            block = Block(self.pool, self.blocks[-1].header['hash'], self.receiver_pool, timestamp= time.strftime("%Y-%m-%d %H:%M:%S UTC+0", time.gmtime(time.time())))
            block.mine(self.difficulty)
            
            if block.Merkle_Tree.check_merkle_root:
                        
                self.add_to_chain(block)     
            
            else:
                print('merkle_root failed.')        
            
            
        else:
            print('NOTHING TO MINE')
