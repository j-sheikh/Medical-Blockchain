# -*- coding: utf-8 -*-
"""
Created on Wed Jan 25 00:34:15 2023

@author: jannik sheikh
"""

import hashlib


class MerkleTree:
    def __init__(self, transactions):

        self.transactions = transactions
        self.transactions_hashes = [hashlib.sha256(str(tx).encode()).hexdigest() for tx in transactions]
        self.merkle_root, self.merkle_branch = self.hash_pairs_with_branch()


    def hash_pairs_with_branch(self):

        current_hashes = self.transactions_hashes
        merkle_branch = []
        while len(current_hashes) > 1:
            if len(current_hashes) % 2 == 1:
                current_hashes.append(current_hashes[-1])
            new_hashes = []
            for i in range(0, len(current_hashes), 2):
                left_hash = current_hashes[i]
                if i+1 < len(current_hashes):
                    right_hash = current_hashes[i+1]
                else:
                    right_hash = hashlib.sha256(b'').hexdigest()
                new_hash = hashlib.sha256((str(left_hash) + str(right_hash)).encode()).hexdigest()
                new_hashes.append(new_hash)
                if len(current_hashes) % 2 == 0:
                    merkle_branch.append(right_hash)
            current_hashes = new_hashes
        return current_hashes[0], merkle_branch


    def check_merkle_root(self):
            
            current_hashes = self.transactions_hashes
            merkle_branch_index = 0
            while len(current_hashes) > 1:
                if len(current_hashes) % 2 == 1:
                    current_hashes.append(current_hashes[-1])
                new_hashes = []
                for i in range(0, len(current_hashes), 2):
                    left_hash = current_hashes[i]
                    if i+1 < len(current_hashes):
                        right_hash = current_hashes[i+1]
                    else:
                        right_hash = self.merkle_branch[merkle_branch_index]
                        merkle_branch_index += 1
                    new_hash = hashlib.sha256((str(left_hash) + str(right_hash)).encode()).hexdigest()
                    new_hashes.append(new_hash)
                current_hashes = new_hashes
            return current_hashes[0] == self.merkle_root



# merkle_tree = MerkleTree([1, 2, 3, 4, 5])
# print(merkle_tree.merkle_root)
# print(merkle_tree.merkle_branch)
# merkle_tree.check_merkle_root()
