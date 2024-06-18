import socket
import threading
import hashlib
import os

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
                        self.users[username] = {'salt': salt, 'password': hashed_password}
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
                            break
                        else:
                            client_socket.send("Error: Invalid username or password.".encode())
                    else:
                        client_socket.send("Error: Invalid username or password.".encode())
                else:
                    client_socket.send("Error: Invalid command.".encode())
                    break

            while True:
                message = client_socket.recv(1024).decode()
                if message:
                    recipient, sender, message_content = message.split(':', 2)
                    if recipient in self.clients:
                        self.clients[recipient].send(f"{sender}: {message_content}".encode())
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
                    username, salt_hex, hashed_password_hex = line.strip().split(",")
                    salt = bytes.fromhex(salt_hex)
                    hashed_password = bytes.fromhex(hashed_password_hex)
                    self.users[username] = {'salt': salt, 'password': hashed_password}

    def save_users(self):
        with open("users.txt", "w") as f:
            for username, data in self.users.items():
                salt_hex = data['salt'].hex()
                hashed_password_hex = data['password'].hex()
                f.write(f"{username},{salt_hex},{hashed_password_hex}\n")


if __name__ == "__main__":
    server = Server()
