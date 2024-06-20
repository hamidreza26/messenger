import socket
import threading
import hashlib
import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class Server:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}
        self.users = {}
        self.load_users()
        self.start()

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Server started on {self.host}:{self.port}")
        while True:
            client_socket, client_address = self.server_socket.accept()
            print(f"New connection from {client_address}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            while True:
                request = client_socket.recv(1024).decode()
                if request.startswith("SIGNUP"):
                    _, username, password = request.split(",")
                    if username in self.users:
                        client_socket.send("Error: Username already exists.".encode())
                    else:
                        salt = os.urandom(32)
                        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
                        private_key, public_key = generate_key_pair()
                        self.users[username] = {
                            'salt': salt,
                            'password': hashed_password,
                            'private_key': base64.b64encode(private_key).decode('utf-8'),
                            'public_key': base64.b64encode(public_key).decode('utf-8')
                        }
                        self.save_users()
                        client_socket.send("Signup successful.".encode())
                elif request.startswith("LOGIN"):
                    _, username, password = request.split(",")
                    if username in self.users:
                        stored_password = self.users[username]['password']
                        salt = self.users[username]['salt']
                        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
                        if hashed_password == stored_password:
                            client_socket.send("Login successful.".encode())
                            self.clients[username] = client_socket
                        else:
                            client_socket.send("Error: Invalid username or password.".encode())
                    else:
                        client_socket.send("Error: Invalid username or password.".encode())

                elif request.startswith("GET_PUBLIC_KEY"):
                    _, receiver = request.split(",")
                    if receiver in self.users:
                        receiver_public_key = self.users[receiver]['public_key']
                        client_socket.send(receiver_public_key.encode())
                    else:
                        client_socket.send("Error: Invalid receiver.".encode())

                elif request.startswith("GET_PRIVATE_KEY"):
                    _, receiver = request.split(",")
                    if receiver in self.users:
                        receiver_private_key = self.users[receiver]['private_key']
                        client_socket.send(receiver_private_key.encode())
                    else:
                        client_socket.send("Error: Invalid receiver.".encode())
                else:
                    client_socket.send("Error: Invalid command.".encode())
                    break

            while True:
                message = client_socket.recv(1024).decode()
                if message:
                    recipient, sender, message_content = message.split(':', 2)
                    if recipient in self.clients:
                        self.clients[recipient].send(message_content.encode())
                    else:
                        client_socket.send(f"Error: User '{recipient}' not found.".encode())
                else:
                    break
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            if client_socket in self.clients.values():
                username = next(key for key, value in self.clients.items() if value == client_socket)
                del self.clients[username]
            client_socket.close()

    def load_users(self):
        if os.path.exists("users.txt"):
            with open("users.txt", "r") as f:
                for line in f:
                    username, salt_hex, hashed_password_hex, public_key_hex, private_key_hex = line.strip().split(",")
                    salt = bytes.fromhex(salt_hex)
                    hashed_password = bytes.fromhex(hashed_password_hex)
                    public_key = base64.b64decode(public_key_hex)
                    private_key = base64.b64decode(private_key_hex)
                    self.users[username] = {'salt': salt, 'password': hashed_password, 'public_key': public_key, 'private_key': private_key}

    def save_users(self):
        with open("users.txt", "w") as f:
            for username, data in self.users.items():
                salt_hex = data['salt'].hex()
                hashed_password_hex = data['password'].hex()
                public_key_hex = base64.b64encode(data['public_key']).decode('utf-8')
                private_key_hex = base64.b64encode(data['private_key']).decode('utf-8')
                f.write(f"{username},{salt_hex},{hashed_password_hex},{public_key_hex},{private_key_hex}\n")

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

if __name__ == "__main__":
    server = Server()
