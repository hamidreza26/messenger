import socket
import threading

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
                    self.start_chat(username)
                    break
            else:
                print("Invalid choice. Please try again.")

    def login(self, username, password):
        self.client_socket.send(f"LOGIN,{username},{password}".encode())
        response = self.client_socket.recv(1024).decode()
        print(response)
        if response == "Login successful.":
            self.start_chat(username)
        else:
            print("Login failed.")
            self.client_socket.close()

    def start_chat(self, username):
        threading.Thread(target=self.receive_messages).start()
        while True:
            recipient = input("Enter recipient's username ('q' to quit): ")
            if recipient.lower() == 'q':
                break
            message = input("Enter your message: ")
            self.send_message(recipient, username, message)

    def send_message(self, recipient, sender, message):
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

if __name__ == "__main__":
    client = Client()
