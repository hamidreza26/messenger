import socket
import threading

import hashlib
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class Client:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect_to_server()

    def connect_to_server(self):
        self.client_socket.connect((self.host, self.port))
        while True:
            choice = input("Do you want to (1) Signup or (2) Login? Enter 1 or 2: ")
            if choice == '1':
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                self.client_socket.send(f"SIGNUP,{username},{password}".encode())
                response = self.client_socket.recv(1024).decode()
                print(response)
                if response == "Signup successful.":
                    self.login(username, password)
                    break
            elif choice == '2':
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                self.client_socket.send(f"LOGIN,{username},{password}".encode())
                response = self.client_socket.recv(1024).decode()
                print(response)
                if response == "Login successful.":
                    self.get_reciever_key(username)
                    break
            else:
                print("Invalid choice. Please try again.")

    def login(self, username, password):
        self.client_socket.send(f"LOGIN,{username},{password}".encode())
        response = self.client_socket.recv(1024).decode()
        print(response)
        if response == "Login successful.":
            self.get_reciever_key(username)
        else:
            print("Login failed.")
            self.client_socket.close()

    def get_reciever_key(self, username):
        recipient = input("Enter recipient's username]: ")
        self.client_socket.send(f"GET_PUBLIC_KEY,{recipient}".encode())
        public_key_pem = self.client_socket.recv(4096)
        #print("publicKey:"+publicKey)
        self.start_chat(username,recipient,public_key_pem)

    def start_chat(self, username,recipient,reciever_public_key):
        threading.Thread(target=self.receive_messages).start()
        while True:
            message = input("Enter your message('q' to quit): ")
            if message.lower() == 'q':
                break
            self.send_message(recipient, username, message,reciever_public_key)

    def send_message(self, recipient, sender, message,reciever_public_key):
        encrypted_message = self.encryptMessage(message,reciever_public_key)
        full_message = f"{recipient}:{sender}:{message}"
        self.client_socket.send(full_message.encode())

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode()
                if message:
                    print(message)
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def encryptMessage(self,message,key):
        public_key = serialization.load_pem_public_key(key, backend=default_backend())
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message
    
if __name__ == "__main__":
    client = Client()
