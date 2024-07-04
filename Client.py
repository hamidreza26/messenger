import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import base64
import random
import os
HOST = 'localhost'
PORT = 5001

Private_Chat = 0
user_ports = {}

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
current_username = None

client_socket.connect((HOST, PORT))

def verify_sign(public_key_pem, encrypted_message, original_message):
    public_key = serialization.load_pem_public_key(
        public_key_pem, 
        backend=default_backend()
    )
    # Controleer of het originele bericht al in bytes-formaat is
    if isinstance(original_message, str):
        original_message = original_message.encode()
    try:
        public_key.verify(
            base64.b64decode(encrypted_message),
            original_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


def send_message(target_ip, target_port,messagefirst):
    global current_username , t2
    try:
        print("1")
        sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sender_socket.connect((target_ip, target_port))
        # message = f"first_message,{current_username},{messagefirst}"
        # print(message)
        
        sender_socket.send(f"FIRST_MESSAGE,{current_username},{messagefirst}".encode())
        print("2")

        while True:
            message = input("(for the leav please write exit): ")
            if message.lower() == 'exit':
                break
            sender_socket.send(message.encode())
        sender_socket.close()
    except Exception as e:
        print(f"خطا در ارسال پیام به {target_ip}:{target_port} - {e}")


        
def receive(client_socket):
    global Private_Chat
    while True:
        try:
            message = client_socket.recv(1024)
            if message.startswith(b"public key is here"):
                print("Step 4: Received encrypted public key from server.")
                parts = message.split(b',', 3)
                if len(parts) == 4:
                    sign = parts[1]
                    print (f"\nis sign\n{sign}\n")
                    target_public_key = parts[2]
                    print (f"\nis target public key \n{target_public_key}\n")
                    target_port = parts[3]
                    print (f"\nis target port \n{target_port}\n")
                    # encrypted_key = bytes.fromhex(encrypted_key_hex.decode())
                    with open("server_public_key.pem", "rb") as f:
                        server_public_key = f.read()
                        print ( server_public_key)
                    is_authentic = verify_sign(server_public_key, sign, target_public_key)
                    if is_authentic:
                        print("Message verify Succsefully.")
                        print(f"Content of Message: {target_public_key}")
                        peer_ip = 'localhost'
                        target_port = int (target_port)
                        message = "salam"
                        Private_Chat = 1
                        sender_thread = threading.Thread(target=send_message, args=(peer_ip, target_port, message))
                        sender_thread.start()




                    else:
                        print("Message Can't Veriy")
                    # print(f"Step 5: Decrypted public key: {decrypted_key.decode()}")
                    # Handle the decrypted key (use it to encrypt messages to the target user)
                else:
                    print("Invalid public key format.")
            else:
                text_area.insert(tk.END, message.decode() + '\n')
        except Exception as e:
            print(f"An error occurred: {e}")
            client_socket.close()
            break

def write(event=None):
    message = entry_message.get()
    if message:
        client_socket.send(message.encode())
        entry_message.delete(0, tk.END)

def on_closing():
    client_socket.close()
    root.destroy()


def encryptMessage(message,key):
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
    

def login_or_register():
    global current_username
    while True:
        action = simpledialog.askstring("Action", "Do you want to 'login' or 'register'?")
        if action == 'login':
            username = simpledialog.askstring("Login", "Enter your username:")
            password = simpledialog.askstring("Login", "Enter your password:", show='*')
            client_socket.send(f"LOGIN,{username},{password}".encode())
            response = client_socket.recv(1024).decode()
            if response == "Login successful.":
                messagebox.showinfo("Info", "Login successful.")
                current_username = username
                break
            else:
                messagebox.showerror("Error", response)
        elif action == 'register':
            username = simpledialog.askstring("Register", "Enter your username:")
            password = simpledialog.askstring("Register", "Enter your password:", show='*')
            client_socket.send(f"REGISTER,{username},{password}".encode())
            response = client_socket.recv(1024).decode()
            if response == "Registration successful.":
                messagebox.showinfo("Info", "Registration successful. Please login now.")
            else:
                messagebox.showerror("Error", response)
        else:
            messagebox.showerror("Error", "Invalid action. Please type 'login' or 'register'.")

def request_chat():
    target = simpledialog.askstring("Request Chat", "Enter the recipient's username:")
    client_socket.send(f"REQUEST_CHAT,{target}".encode())
    print(f"Step 1: Sent chat request to {target}")


def request_chat2(target):
    # target = simpledialog.askstring("Request Chat", "Enter the recipient's username:")
    client_socket.send(f"REQUEST_CHAT,{target}".encode())
    print(f"Step 1: Sent chat request to {target}")


root = tk.Tk()
root.title("Simple Messenger")

login_or_register()



port_for_listen = random.randint(1024, 65535)


print(f"its random port for listening: {port_for_listen}")
if os.path.exists('port.txt'):
    with open('port.txt', 'r') as f:
        for line in f:
            username, port = line.strip().split(', ')
            user_ports[username] = int(port)



# تابعی برای مدیریت پیام‌های ورودی
def handle_incoming_messages(client_socket):
    global Private_Chat
    message = client_socket.recv(1024).decode()
    if message.startswith("FIRST_MESSAGE") and Private_Chat == 0:
        parts = message.split(',')
        if len(parts) == 3:
            print("4")
            sender_username = parts[1]
            firstmessage = parts[2]
            print(firstmessage)
            print(sender_username)
            print(f"Step 1: try for give the pub key from {sender_username}")
            request_chat2(sender_username)
    while True:

        print("3")
        try:
            message = client_socket.recv(1024).decode()
            print(message)
            if not message:
                break
            print(f"\nMassege Recive: {message}")
        except:
            client_socket.close()
            break



def listen_for_messages(port):
    listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener_socket.bind(('localhost', port))
    listener_socket.listen(1)
    print(f"کلاینت در پورت {port} منتظر اتصال است...")

    while True:
        client_socket, addr = listener_socket.accept()
        print(f"اتصال جدید از {addr}")
        client_handler = threading.Thread(target=handle_incoming_messages, args=(client_socket,))
        client_handler.start()


user_ports[current_username] = port_for_listen


with open('port.txt', 'w') as f:
    for username, port in user_ports.items():
        f.write(f"{username}, {port}\n")

print(f"Successfully saved port for listen {port_for_listen} and username {current_username}.")

# Start Thread for listen Message 
listener_thread = threading.Thread(target=listen_for_messages, args=(port_for_listen,))
listener_thread.start()
            
# Text display area
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=40, height=20)
text_area.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

# Entry for typing messages
entry_message = tk.Entry(root, width=30)
entry_message.grid(row=1, column=0, padx=10, pady=10)

# Bind the Enter key to the write function
entry_message.bind("<Return>", write)

# Send button
send_button = tk.Button(root, text="Send", command=write)
send_button.grid(row=1, column=1, padx=10, pady=10)

# Close button
close_button = tk.Button(root, text="Close", command=on_closing)
close_button.grid(row=2, column=0, columnspan=2, pady=10)

# Request Chat button
request_chat_button = tk.Button(root, text="Request Chat", command=request_chat)
request_chat_button.grid(row=3, column=0, columnspan=2, pady=10)

# Start the thread for receiving messages
receive_thread = threading.Thread(target=receive, args=(client_socket,))
receive_thread.start()

# Start the tkinter main loop
root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()