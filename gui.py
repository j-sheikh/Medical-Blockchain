import tkinter as tk
import rsa
from myp2pnode import MyOwnPeer2PeerNode
import hashlib
import os
import pickle
import json
import time
import tkinter.messagebox
import sys
import requests
import base64
from tkinter import filedialog
from PIL import Image
import pandas as pd
import io
import gzip
import socket

gitkey_path = r'C:\Users\janni\Documents\Stuff\git_blockchain.txt'
class SharingDoc:
    def __init__(self, sys_argv):
        self.root = tk.Tk()
        # self.ip = "127.0.0.1"
        # self.port = 9875
        self.load_user_dict()
        self.privkey = None
        self.pubkey =  None
        self.user = None
        self.log1n = False
        self.node = None

        if len(sys_argv) > 1:
            self.port = int(sys_argv[1])
        if len(sys_argv) > 2:
            self.ip = sys_argv[1]
            self.port = int(sys_argv[2])

        self.root.iconify()
        self.main()   
        
    def status_adding_data(self, message):
        self.text_area.insert(tk.END, message)
   
    def share_pubkey(self):
        if self.my_pubkey_callback:
            self.message_callback(self.pubkey)
    
    def receive_message(self, node, data):
        message = f"\nFrom {node.id}: {data}"
        self.text_area.insert(tk.END, message)
        
    def inbound_message(self, node):
        message = f"You are now connected with the following node: {node.id}"
        self.text_area.insert(tk.END, message)
        
    def inbound_disconnect_message(self, node):
        message = f"You are now disconnected with the following node: {node.id}"
        self.text_area.insert(tk.END, message)


    def chain_data(self, blocks):
        
        start_message = '\n\n################################PRINT CHAIN START###############################\n\n'
        end_message = '\n\n################################PRINT CHAIN END#################################\n\n'
        self.text_area.insert(tk.END, start_message)
        for i in range(len(blocks)):
            message = (f"\n\n============START BLOCK {i} =================\n\nHeader:{blocks[i].header}\n\nBody:{blocks[i].body}\n\n=============END BLOCK {i}===================\n\n")
            self.text_area.insert(tk.END, message)
        self.text_area.insert(tk.END, end_message)
        
    def get_my_data(self, blocks):
           
        view_data_window = tk.Toplevel(main_window)
        view_data_window.lift()
        view_data_window.attributes("-topmost", True)
        view_data_window.title("View Data")
        message_label = tk.Label(view_data_window, text="Your data: ")
        message_label.pack()
        message_entry = tk.Text(view_data_window,  height=10, width=40)
        message_entry.pack(fill='both', expand=True)

        current_block = 0
        def display_block(current_block):
            for k in blocks[current_block].body.keys():
                if k in ['data', f'data_{self.pubkey}']:
                    value = blocks[current_block].body[k]
                    if k == 'data':
                        message = f"\n\n================\n\nAdded: {blocks[current_block].header['timestamp']}\n{value}"
                    else:

                        decoded = rsa.decrypt(value[0], self.privkey)
                        message = f"\n\n================\n\nAdded: {blocks[current_block].header['timestamp']}\n{decoded.decode('ascii')}"

            message_entry.delete("1.0", tk.END)
            message_entry.insert(tk.END, message)

        display_block(current_block)

        next_button = tk.Button(view_data_window, text="Next", command=lambda: display_block(current_block))
        next_button.pack()
        prev_button = tk.Button(view_data_window, text="Previous", state = 'disable', command=lambda: display_block(current_block))
        prev_button.pack()

        def on_next():
            nonlocal current_block
            current_block += 1
            if current_block >= len(blocks):
                current_block = len(blocks) - 1
            display_block(current_block)
            if current_block == len(blocks) - 1:
                next_button.config(state='disabled')
            prev_button.config(state='normal')

        def on_prev():
            nonlocal current_block
            current_block -= 1
            if current_block < 0:
                current_block = 0
            display_block(current_block)
            if current_block == 0:
                prev_button.config(state='disabled')
            next_button.config(state='normal')

        next_button.config(command=on_next)
        prev_button.config(command=on_prev)

        if len(blocks) == 1:
            next_button.config(state='disabled')
            prev_button.config(state='disabled')

    def main(self):
        self.build_login_gui()
        self.root.mainloop()
      
    def build_login_gui(self):
        global login_window
        login_window = tk.Toplevel(self.root)
        login_window.lift()
        login_window.attributes("-topmost", True)
        login_window.title("SharingDoc LogIn")
        login_window.geometry("600x500")
        
        self.username_label = tk.Label(login_window, text="Username:")
        self.username_entry = tk.Entry(login_window)

        self.password_label = tk.Label(login_window, text="Password:")
        self.password_entry = tk.Entry(login_window, show="*")

        
        self.ip_label = tk.Label(login_window, text="IP-Adress:")
        self.ip_entry = tk.Entry(login_window)

        self.port_label = tk.Label(login_window, text="Port:")
        self.port_entry = tk.Entry(login_window)

        
        self.login_button = tk.Button(login_window, text="Login", command=self.login)
        self.for_pw_button = tk.Button(login_window, text="Forgot Password", command=self.forgot_password)
        self.signup_button = tk.Button(login_window, text="Sign-Up", command=self.signup)
        
        
        self.username_label.pack()
        self.username_entry.pack()
        self.password_label.pack()
        self.password_entry.pack()
        
        self.ip_label.pack()
        self.ip_entry.pack()  
        self.port_label.pack()
        self.port_entry.pack()
        
        
        self.login_button.pack()
        self.for_pw_button.pack()
        self.signup_button.pack()
        

    def send_message(self):
        checkbox_window = tk.Toplevel(main_window)
        checkbox_window.lift()
        checkbox_window.attributes("-topmost", True)
        checkbox_window.title("Send Message: ")
        message_label = tk.Label(checkbox_window, text="Enter message:")
        message_label.pack()
        message_entry = tk.Text(checkbox_window,  height=10, width=40)
        message_entry.pack()

        checkbox_vars = []
        for key in self.user_dict.keys():
            if key in self.node.connected_users.keys():
                checkbox_var = tk.IntVar()
                checkbox_vars.append(checkbox_var)
                tk.Checkbutton(checkbox_window, text=key, variable=checkbox_var).pack()

        def get_receivers():
            receivers = []

            for i, key in enumerate(self.node.connected_users.keys()):
                if checkbox_vars[i].get() == 1:
                    receivers.append(key)
            return receivers

        send_button = tk.Button(checkbox_window, text="Send", state = "disabled", command=lambda: (self.node.node_send_private_message(message_entry.get("1.0", "end"), get_receivers()),
                                                                                                   self.text_area.insert(tk.END, f'\n{self.node.id}: {message_entry.get("1.0", "end")}'),
                                                                                                   checkbox_window.destroy()))

        def validate():
            if len(get_receivers()) == 0 or len(message_entry.get("1.0", "end").strip()) == 0:
                send_button.config(state="disabled")
            else:
                send_button.config(state="normal")

        message_entry.bind("<Key>", lambda e: validate())
        for checkbox_var in checkbox_vars:
            checkbox_var.trace("w", lambda *args: validate())
        send_button.pack()

        
                
        
    def build_main_gui(self):
        global main_window
        main_window = tk.Toplevel(self.root)
        main_window.lift()
        main_window.attributes("-topmost", True)
        main_window.title(f"Welcome {self.user} -- {self.port}")
      
        
        # Create the taskbar frame on the right side
        taskbar = tk.Frame(main_window, bg="gray", width=40, height=10)
        taskbar.pack(side="right")

        # Add buttons to the taskbar
        send_message_button = tk.Button(taskbar, text="Send Message", command=self.send_message)
        send_message_button.pack(fill='x', expand=True)
        if len(self.node.connected_users.keys()) == 0:
            send_message_button.config(state='disabled')
        else:
            send_message_button.config(state='normal')
             
        
        def refresh_send_message_button():
           
            if len(self.node.connected_users.keys()) == 0:
                send_message_button.config(state='disabled')
            else:
                send_message_button.config(state='normal')
            main_window.after(100, refresh_send_message_button)
        

        connect_button = tk.Button(taskbar, text="Connect", command=self.connect)
        connect_button.pack(fill="x")
        
        
        disconnect_button = tk.Button(taskbar, text="Disconnect", command= self.disconnect)
        disconnect_button.pack(fill='x')
        
        print_chain_button = tk.Button(taskbar, text="Print Chain", command=self.node.chain.display_chain)
        print_chain_button.pack(fill='x')
        
        add_to_chain_button = tk.Button(taskbar, text="Add to Chain", command=self.add_to_chain)
        add_to_chain_button.pack(fill='x')
        
        get_my_data_button = tk.Button(taskbar, text="View my data", command=self.node.chain.search_chain_for_data)
        get_my_data_button.pack(fill='x')
        
              
        
        logout_button = tk.Button(taskbar, text="Logout", command=self.logout)
        logout_button.pack(fill="x")
              
        # Add a text area on the left side
        self.text_area = tk.Text(main_window, bg="white", height=30, width=80)
        self.text_area.pack(fill = 'both', expand = True, side="left")
     
        main_window.after(100, refresh_send_message_button)   

           
    def add_to_chain(self):
        add_window = tk.Toplevel(main_window)
        add_window.title("Add data to chain: ")
        add_window.lift()
        add_window.attributes("-topmost", True)
        message_label = tk.Label(add_window, text="Enter data or upload file:")
        message_label.pack()
        message_entry = tk.Text(add_window,  height=10, width=40)
        message_entry.pack(expand=True, fill='both')
        
        checkbox_vars = []
        users = list(self.user_dict.keys())
        users.append('ALL')

        for key in users:       
            checkbox_var = tk.IntVar()
            checkbox_vars.append(checkbox_var)
            tk.Checkbutton(add_window, text=key, variable=checkbox_var).pack()

        def get_receivers(users=users):
            receivers = []

            for i, key in enumerate(users):
                if checkbox_vars[i].get() == 1:
                    receivers.append(key)
            return receivers
        
        
        def encrypt_data(users=users):
            new_data = []
            new_unames = []
            new_receivers = []    
            
            receivers = get_receivers(users=users)
            data = message_entry.get("1.0", "end")
            for rec in receivers:
                if rec not in new_unames:
                    if rec == 'ALL':
                        new_data.append(data)
                        new_unames.append('ALL')
                        new_receivers.append('ALL')
                    else:
                        pub_key = self.user_dict[rec]['public_key']
                        encData = rsa.encrypt(data.encode('utf-8'), pub_key)
                        new_data.append(encData)
                        new_unames.append(rec)
                        new_receivers.append(str(pub_key))
                        
            return new_data, new_receivers    
        
        def on_data_entry_change(*args):
            data = message_entry.get("1.0", "end")
            if data.strip():
                add_button.config(state="normal")
            else:
                add_button.config(state="disabled")
    
        message_entry.bind("<Key>", on_data_entry_change)
        message_entry.bind("<Button-1>", on_data_entry_change)
        
        add_button = tk.Button(add_window, text="Add", state = "disabled", command=lambda: (self.node.chain.add_to_pool(encrypt_data()[0], encrypt_data()[1]),
                                                                                            add_window.destroy()))
        add_button.pack()
        
        def upload_file():
            file_path = filedialog.askopenfilename()
            if not file_path:
                return
            extension = file_path.split(".")[-1].lower()
            try:
                with open(file_path, 'rb') as file:
                    if extension == 'csv':
                        df = pd.read_csv(file)
                        contents = df.to_json().encode('utf-8')
                        contents = gzip.compress(contents)
                    elif extension == 'json':
                        contents = file.read()
                        contents = gzip.compress(contents)
                    elif extension in ['jpg', 'jpeg', 'png']:
                        image = Image.open(file)
                        size = (28, 28)
                        resized_image = image.resize(size)
                        buffer = io.BytesIO()
                        resized_image.save(buffer, format="PNG")
                        contents = base64.b64encode(buffer.getvalue()).decode()
                        contents = gzip.compress(contents.encode('utf-8'))
                    else:
                        raise Exception("Unsupported file type")
                    message_entry.delete("1.0", tk.END)
                    message_entry.insert(tk.END, contents)
            except Exception as e:
                tk.messagebox.showerror("Error", str(e))
                    
                
        upload_button = tk.Button(add_window, text="Upload file", command=upload_file)
        upload_button.pack()

        def validate():
            if len(get_receivers()) == 0 or len(message_entry.get("1.0", "end").strip()) == 0:
                add_button.config(state="disabled")
            else:
                add_button.config(state="normal")

        message_entry.bind("<Key>", lambda e: validate())
        for checkbox_var in checkbox_vars:
            checkbox_var.trace("w", lambda *args: validate())
        add_button.pack()
    
    
    def forgot_password(self):
        # create a new window
        global fp_window
        fp_window = tk.Toplevel(self.root)
        fp_window.lift()
        fp_window.attributes("-topmost", True)
        fp_window.title("Forgot Password")
        fp_window.geometry("400x200+100+100")
    
        # add a label for username
        username_label = tk.Label(fp_window, text="Username:")
        username_label.grid(row=0, column=0, padx=10, pady=10)
    
        # add an entry for username
        username_entry = tk.Entry(fp_window)
        username_entry.grid(row=0, column=1, padx=10, pady=10)
    
        # add a label for safety question
        safety_question_label = tk.Label(fp_window, text="What is your first pet's name?")
        safety_question_label.grid(row=1, column=0, padx=10, pady=10)
    
        # add an entry for safety question
        safety_question_entry = tk.Entry(fp_window, show="*")
        safety_question_entry.grid(row=1, column=1, padx=10, pady=10)
    
        # add a button for submit
        submit_button = tk.Button(fp_window, text="Submit", command=lambda: submit(username_entry.get(), safety_question_entry.get()))
        submit_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10)
    
    
        def update_password(username, new_password, confirm_password):
            print(new_password, confirm_password)
            if new_password == confirm_password:
                  
                new_salt = os.urandom(32)
                new_key = hashlib.pbkdf2_hmac('sha256', new_password.encode('utf-8'), new_salt, 100000)
                self.user_dict[username]['key_pw'] = new_key
                self.user_dict[username]['salt_pw'] = new_salt
                self.upload_user_dict()
               
                tk.messagebox.showinfo("Info", "Password saved")
                pc_window.destroy()
                fp_window.destroy()
                time.sleep(5)
                self.load_user_dict()
            else:
                tk.messagebox.showerror("Error", "Passwords do not match. Try again.")
                pc_window.destroy()
                fp_window.destroy()
                
                
        def submit(username, safety_question):
            if username in self.user_dict:
                
                salt_secq = self.user_dict[username]['salt_secq']
                key_secq = self.user_dict[username]['key_secq']
                new_secq = hashlib.pbkdf2_hmac('sha256', safety_question.encode('utf-8'), salt_secq, 100000)

                if key_secq == new_secq:
                    # create a new window for password change
                    global pc_window
                    pc_window = tk.Toplevel(fp_window)
                    pc_window.title("Change Password")
                    pc_window.geometry("400x200+100+100")
                    
                    def check_password_match(password, confirm_password):
                        if password == "" and confirm_password == "":
                            password_match_label.config(text="Enter a Password", fg="red")
                            return False
                        
                        elif password == confirm_password:
                            password_match_label.config(text="Password matched", fg="green")
                            return True
                        else:
                            password_match_label.config(text="Password do not match", fg="red")
                            return False
                    
                    # create password input boxes and match label
                    password_label = tk.Label(pc_window, text="Password:")
                    password_entry = tk.Entry(pc_window, show="*")
                    confirm_password_label = tk.Label(pc_window, text="Confirm Password:")
                    confirm_password_entry = tk.Entry(pc_window, show="*")
                    password_match_label = tk.Label(pc_window, text="", fg="red")
                    
                    # bind the check_password_match function to the password and confirm password entry widgets
                    confirm_password_entry.bind("<KeyRelease>", lambda event: check_password_match(password_entry.get(), confirm_password_entry.get()))
                    
                    password_label.pack()
                    password_entry.pack()
                    confirm_password_label.pack()
                    confirm_password_entry.pack()
                    password_match_label.pack()     
                    

    
                    # add a button for save
                    save_button = tk.Button(pc_window, text="Save", state="disabled", command= lambda: update_password(username, password_entry.get(), confirm_password_entry.get()))

                    
                    
                    def show_save_button():
                        if check_password_match(password_entry.get(), confirm_password_entry.get()):
                            save_button.config(state="normal")
                        else:
                            save_button.config(state="disabled")
                    
                    # bind the show_save_button function to each of the three check functions
                    confirm_password_entry.bind("<KeyRelease>", lambda event: show_save_button())
                    
                    # display the "Save" button
                    save_button.pack()
                    
                else:
                    tk.messagebox.showerror("Error", "Incorrect answer")
                    fp_window.destroy()
            
            else:
               tk.messagebox.showerror("Error", "Username not found")
               fp_window.destroy()

    
    
    
    def signup(self):
        
        # create a new window
        global sp_window
        sp_window = tk.Toplevel(self.root)
        sp_window.lift()
        sp_window.attributes("-topmost", True)
        sp_window.title("Sign-Up")
        sp_window.geometry("400x400+100+100")
        
        def check_username_availability(username):
            if username == "":
                username_availability_label.config(text="Enter a Username", fg="red")
                return False
            
            elif username in self.user_dict.keys():
                username_availability_label.config(text="Username not available", fg="red")
                return False
            else:
                username_availability_label.config(text="Username available", fg="green")
                return True
        
        def check_password_match(password, confirm_password):
            if password == "" and confirm_password == "":
                password_match_label.config(text="Enter a Password", fg="red")
                return False
            
            elif password == confirm_password:
                password_match_label.config(text="Password matched", fg="green")
                return True
            else:
                password_match_label.config(text="Password do not match", fg="red")
                return False

        def check_security_question_answer_match(answer, confirm_answer):
            
            if answer == "" and confirm_answer == "":
                security_question_answer_match_label.config(text="Enter an Answer", fg="red")
                return False
                
            elif answer == confirm_answer:
                security_question_answer_match_label.config(text="Answer matched", fg="green")
                return True
            else:
                security_question_answer_match_label.config(text="Answer do not match", fg="red")
                return False


        # create username input box and availability label
        username_label = tk.Label(sp_window, text="Username:")
        username_entry = tk.Entry(sp_window)
        username_availability_label = tk.Label(sp_window, text="", fg="red")
        
        # bind the check_username_availability function to the username entry widget
        username_entry.bind("<KeyRelease>", lambda event: check_username_availability(username_entry.get()))
        
        # create password input boxes and match label
        password_label = tk.Label(sp_window, text="Password:")
        password_entry = tk.Entry(sp_window, show="*")
        confirm_password_label = tk.Label(sp_window, text="Confirm Password:")
        confirm_password_entry = tk.Entry(sp_window, show="*")
        password_match_label = tk.Label(sp_window, text="", fg="red")
        
        # bind the check_password_match function to the password and confirm password entry widgets
        confirm_password_entry.bind("<KeyRelease>", lambda event: check_password_match(password_entry.get(), confirm_password_entry.get()))
        
        # create security question answer input boxes and match label
        security_question_answer_label = tk.Label(sp_window, text="Answer:")
        security_question_answer_entry = tk.Entry(sp_window, show="*")
        confirm_security_question_answer_label = tk.Label(sp_window, text="Confirm Answer:")
        confirm_security_question_answer_entry = tk.Entry(sp_window, show="*")
        security_question_answer_match_label = tk.Label(sp_window, text="", fg="red")
        
        # bind the check_security_question_answer_match function to the security question answer and confirm answer entry widgets
        confirm_security_question_answer_entry.bind("<KeyRelease>", lambda event: check_security_question_answer_match(security_question_answer_entry.get(), confirm_security_question_answer_entry.get()))
        
        # display
        
        username_label.pack()
        username_entry.pack()
        username_availability_label.pack()
    
        password_label.pack()
        password_entry.pack()
        confirm_password_label.pack()
        confirm_password_entry.pack()
        password_match_label.pack()     
        
        security_question_answer_label.pack()
        security_question_answer_entry.pack()
        confirm_security_question_answer_label.pack()
        confirm_security_question_answer_entry.pack()
        security_question_answer_match_label.pack()
        
        # save userdata to user_dict
        def save_userdata(username, password, security_question):
            salt = os.urandom(32)
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            
            salt_secq = os.urandom(32)
            key_secq = hashlib.pbkdf2_hmac('sha256', security_question.encode('utf-8'), salt_secq, 100000)
                
            (pubkey, privkey) = rsa.newkeys(1024)
            
            directory = "keys"
            if not os.path.exists(directory):
               os.makedirs(directory)
               
            with open('keys/public.pem', 'wb+') as f:
                pk = pubkey.save_pkcs1('PEM')
                f.write(pk)
                
            
            with open('keys/private.pem', 'wb+') as f:
                pk = privkey.save_pkcs1('PEM')
                f.write(pk)
            
            
            self.user_dict[username] = {'public_key': pubkey,
                                'salt_pw':salt,
                                'key_pw': key,
                                'salt_secq': salt_secq,
                                'key_secq': key_secq
                                
            }
            
            self.upload_user_dict()
            
            tk.messagebox.showinfo("Info", "You have successfully signed up.")
            time.sleep(2)
            self.load_user_dict()
            sp_window.destroy()
        # create the "Save" button and set it to be hidden by default
        save_button = tk.Button(sp_window, text="Save", state="disabled", command= lambda: save_userdata(username_entry.get(), password_entry.get(), security_question_answer_entry.get()))
        
        
        def show_save_button():
            if check_username_availability(username_entry.get()) and check_password_match(password_entry.get(), confirm_password_entry.get()) and check_security_question_answer_match(security_question_answer_entry.get(), confirm_security_question_answer_entry.get()):
                save_button.config(state="normal")
            else:
                save_button.config(state="disabled")
        
        # bind the show_save_button function to each of the three check functions
        username_entry.bind("<KeyRelease>", lambda event: show_save_button())
        confirm_password_entry.bind("<KeyRelease>", lambda event: show_save_button())
        confirm_security_question_answer_entry.bind("<KeyRelease>", lambda event: show_save_button())
        
        # display the "Save" button
        save_button.pack()

    
    
    def login(self):
        
        uname = self.username_entry.get()
        password = self.password_entry.get()
        
        if self.ip_entry.get():
            self.ip = int(self.ip_entry.get())
        else:
            host_name = socket.gethostname()
            host_ip = socket.gethostbyname(host_name)
            self.ip = host_ip
        
        if self.port_entry.get():
            self.port = self.port_entry.get()
        else:
            self.port = 9875
            
        if not self.user_dict or uname not in self.user_dict:
            
            self.username_entry.delete(0, 'end')
            self.password_entry.delete(0, 'end')
            self.ip_entry.delete(0, 'end')
            self.port_entry.delete(0, 'end')
            tk.messagebox.showerror("Login", "Username does not exist", parent=login_window)

        else:    
            salt = self.user_dict[uname]['salt_pw']
            key = self.user_dict[uname]['key_pw']
            new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            if key != new_key:
                # self.username_entry.delete(0, 'end')
                self.password_entry.delete(0, 'end')
                tk.messagebox.showerror("Login", "Incorrect password", parent=login_window)
                
            else:
                self.log1n = True
                self.user = uname
                self.load_private_key()
                self.load_public_key()
                self.load_user_dict()
                tk.messagebox.showinfo("Login", "Login successful", parent=login_window)
                login_window.destroy()
                self.node = MyOwnPeer2PeerNode(self.ip, self.port, self.user)
                self.node.start()
                self.node.chain.set_pubkey(self.pubkey)
                self.node.set_message_callback(self.receive_message)
                self.node.set_message_inbound(self.inbound_message)
                self.node.set_message_inbound_disconnect(self.inbound_disconnect_message)
                self.node.chain.set_message_callback(self.chain_data)
                self.node.chain.set_my_data_callback(self.get_my_data)
                self.node.chain.set_satus_callback(self.status_adding_data)

                self.build_main_gui()

    def disconnect(self):
                    
        disconnect_window = tk.Toplevel(main_window)
        disconnect_window.title("Disconnect with other node")
        disconnect_window.geometry("400x400")
        
        checkbox_vars = []

        for key in self.node.connected_users.keys():
            checkbox_var = tk.IntVar()
            checkbox_vars.append(checkbox_var)
            tk.Checkbutton(disconnect_window, text=key, variable=checkbox_var).pack()

        def get_receivers():
            receivers = []

            for i, key in enumerate(self.node.connected_users.keys()):
                if checkbox_vars[i].get() == 1:
                    receivers.append(key)
            return receivers

        disconnect_button = tk.Button(disconnect_window, text="Disconnect", state = "disabled", command=lambda: (self.node.disconnect_with_node(get_receivers()),
                                                                                                   self.text_area.insert(tk.END, f"\nYou are now disconnected with: {i for i in get_receivers()}"),
                                                                                                   disconnect_window.destroy()))

        def validate():
            if len(get_receivers()) == 0:
                disconnect_button.config(state="disabled")
            else:
                disconnect_button.config(state="normal")

        
        for checkbox_var in checkbox_vars:
            checkbox_var.trace("w", lambda *args: validate())
        disconnect_button.pack()

        

    def connect(self):
        

            
        connect_window = tk.Toplevel(main_window)
        connect_window.title("Connect with other node")
        connect_window.geometry("400x400")
        
        # create ip and port input box
        ip_label = tk.Label(connect_window, text="IP Adress:")
        ip_entry = tk.Entry(connect_window)
        
        port_label = tk.Label(connect_window, text="PORT:")
        port_entry = tk.Entry(connect_window)
        
        ip_label.pack()
        ip_entry.pack()
        port_label.pack()
        port_entry.pack()
        
        
        def connect_to_input_node():
            host = ip_entry.get()
            port = int(port_entry.get())
            
            connected = self.node.connect_with_node(host, port)

            if connected:
                target_node = list(self.node.connected_users.keys())[-1]    
                message = f"You are now connected with the following node: {target_node}"
                self.text_area.insert(tk.END, message)
                connect_window.destroy()
            else:
                tk.messagebox.showinfo("Connection", f"Connection with {host}:{port} failed. Try again.")
                connect_window.destroy()
                
        connect_button = tk.Button(connect_window, text="Connect", command=connect_to_input_node)
        connect_button.pack()

            
    def start(self):
        self.node.start()
        time.sleep(1)

    def stop(self):
        self.node.stop()
        time.sleep(1)
            
    def logout(self):
        self.log1n = False
        tk.messagebox.showinfo("Logout", "You have been logged out.", parent=main_window)
        self.stop()
        main_window.destroy()
        time.sleep(3)
        os.execl(sys.executable, sys.executable, *sys.argv)

        # self.main()
                
    def load_private_key(self):
        with open('keys/private.pem', mode='rb') as privatefile:
            keydata = privatefile.read()
        self.privkey = rsa.PrivateKey.load_pkcs1(keydata)


    def load_public_key(self):
        with open('keys/public.pem', mode='rb') as publicfile:
            keydata = publicfile.read()
        self.pubkey = rsa.PublicKey.load_pkcs1(keydata)
    
    # def save_user_dict(self):

    #     with open('users.pickle', 'wb') as f:
    #         pickle.dump(self.user_dict, f, protocol=pickle.HIGHEST_PROTOCOL)  
     
    # def load_user_dict(self):
    #     try:
    #         with open('users.pickle', 'rb') as f:
    #             self.user_dict = pickle.load(f)   
    #     except:
    #         self.user_dict = {}     
            
            
    def upload_user_dict(self):
        
        def load_git_token():
            with open(gitkey_path, 'r') as f:
                return f.read()
            
        # your Github token
        token = load_git_token()

        
        # the URL for the file you want to update
        url = "https://api.github.com/repos/j-sheikh/Medical-Blockchain/contents/users.pickle"

        # encoding the dictionary as binary data
        pickled_data = pickle.dumps(self.user_dict, protocol=pickle.HIGHEST_PROTOCOL)  
        # b64_content = base64.b64encode(pickled_data).decode()
        
        # checking if the file exists
        get_response = requests.get(url, headers={
            "Authorization": f"Token {token}"
        })
        # print(get_response.status_code)
        if get_response.status_code == 404:
            create_data = {
                "message": "Create users.pickle",
                "content": base64.b64encode(pickled_data).decode()
            }
             
            response = requests.put(url, headers={
                "Authorization": f"Token {token}",
                "Content-Type": "application/json"
            }, json=create_data)
         
        
            if response.status_code == 201:
                print("File created successfully")
            else:
                print("Failed to create file")
            
    
        elif get_response.status_code == 200:
            
            # updating the file with a PUT request
            response = requests.put(url, headers={
                "Authorization": f"Token {token}",
            })
            sha = get_response.json()["sha"]
            b64_content = base64.b64encode(pickled_data).decode()
            update_data = {
                "message": "Update users.pickle",
                "content": b64_content,
                "sha": sha
            }
            response = requests.put(url, headers={
                "Authorization": f"Token {token}",
                "Content-Type": "application/json"
            }, json=update_data)
            
            if response.status_code == 200:
                print("File updated successfully")
            else:
                print("Failed to update file")
        else:
            print("Error while checking if file exists")
        

            
    
    def load_user_dict(self):
        
        url = "https://api.github.com/repos/j-sheikh/Medical-Blockchain/contents/users.pickle"

        response = requests.get(url)

        if response.status_code == 200:
            contents = response.json()["content"]
            decoded_content = base64.b64decode(contents)
            self.user_dict = pickle.loads(decoded_content)
        else:
            print('Error')
            self.user_dict = {}
                        
