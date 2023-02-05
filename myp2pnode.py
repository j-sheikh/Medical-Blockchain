# -*- coding: utf-8 -*-
"""
Created on Wed Oct 19 10:32:43 2022

@author: Jannik Sheikh
"""

# from p2pnetwork.node import Node
from Node import Node
from Chain import Chain
from Block import Block
import time

class MyOwnPeer2PeerNode(Node):


    def __init__(self, host, port, id=None,  callback=None, max_connections=0):
        super(MyOwnPeer2PeerNode, self).__init__(host, port, id,  callback, max_connections)
        self.connected_users = {}
        self.message_callback = None
        self.message_inbound_callback = None
        self.message_inbound_disconnect_callback = None
        self.chain = Chain(10)
        
        print("MyPeer2PeerNode: Started")


    # All the methods below are called when things happen in the network.
    # implement your network node behavior to create the required functionality.
    
    def set_message_callback(self, callback):
        self.message_callback = callback
        

    def set_message_inbound(self, callback):
        self.message_inbound_callback = callback
    
    def set_message_inbound_disconnect(self, callback):
        self.message_inbound_disconnect_callback = callback
        
    def outbound_node_connected(self, node):       
        self.connected_users[node.id] = {'host':node.host, 'port': node.port}

   
    def inbound_node_connected(self, node):
        self.connected_users[node.id] = {'host':node.host, 'port': node.port}
        if self.message_inbound_callback:
            self.message_inbound_callback(node)


    def inbound_node_disconnected(self, node):
        del self.connected_users[node.id]
        if  self.message_inbound_disconnect_callback:
            self.message_inbound_disconnect_callback(node)
        print("inbound_node_disconnected: (" + self.id + "): " + node.id)

    
    def outbound_node_disconnected(self, node):
        
        del self.connected_users[node.id]
        print("outbound_node_disconnected: (" + self.id + "): " + node.id)

    def node_message(self, node, data):
        print('TYPE DATA')
        print(type(data))
        print(data)
        
        if(type(data) is Block):
            print(True)
            self.chain.add_foreign_block(data)
            if(data == self.chain.blocks[-1]):
                self.spread_change(node)

        else:
            self.message_callback(node, data)
      
    def node_disconnect_with_outbound_node(self, node):
        print("node wants to disconnect with other outbound node: (" + self.id + "): " + node.id)
        
    def node_request_to_stop(self):
        print("node is requested to stop (" + self.id + "): ")
        
    def node_send_private_message(self, data, username):
                     
        i = 0
        for n in self.nodes_inbound:
            if n.id in username:
                # print(n.id)
                self.send_to_node(n, data)
                i += 1
        for n in self.nodes_outbound:
            if n.id in username:
                # print(n.id)
                self.send_to_node(n, data)
                i += 1
        if i == 0:
            print("Something went wrong. Please try again.")

                       
    def print_connections(self):
        print(f"YOU ARE CONNECTED WITH: {self.connected_users}.")
        
    def spread_change(self, transmitter, compression='none'):
        text = f'\n{time.strftime("%Y-%m-%d %H:%M:%S UTC+0", time.gmtime(time.time()))}\tA new block has been added to your chain.'
        new_received_block = self.chain.blocks[-1] 
        
        if self.nodes_inbound:
            for n in self.nodes_inbound:
                if (n.id != transmitter.id):
                    self.send_to_node(n, new_received_block, compression)
        if self.nodes_outbound:            
            for n in self.nodes_outbound:
                if (n.id != transmitter.id):
                    self.send_to_node(n,text, compression)
                    self.send_to_node(n,new_received_block, compression)        
                    
   