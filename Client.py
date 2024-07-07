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
PORT = 5009

private_keys_dir = "private_keys/"
Publickey_keys_dir = "public_keys/"
Group_id_dir = "Group_id_dir/"
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


def sign_message(private_key_pem, message):
    private_key = serialization.load_pem_private_key(
        private_key_pem, 
        password=None, 
        backend=default_backend()
    )
    # Controleer of het bericht al in bytes-formaat is
    if isinstance(message, str):
        message = message.encode()
    
    encrypted = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(encrypted).decode()


def send_message_on_group(id):
    global Group_id_dir , current_username
    message = input(f"Enter the Message on Group with id {id}: ")
    target_ip = 'localhost'
    private_key = load_keys(current_username)
    print(private_key)
    sign = sign_message(private_key,message)
    # if isinstance(sign, bytes):
    #     sign = sign.decode('utf-8')
    message_for_send = f"its_group,{current_username},{id},{sign},{message}"
    try:
        with open(f"{Group_id_dir}{id}_group_id.txt", "r") as f:
            for line in f:
                if line.strip():  # Skip empty lines
                    parts = line.strip().split(':')
                    if len(parts) == 3:
                        username, port,role = parts
                        port = int(port)  # Convert port to integer
                        print(f"Sending message to {username} on port {port}")
                        sender_socket3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sender_socket3.connect((target_ip, port))
                        sender_socket3.send(message_for_send.encode())
                        sender_socket3.close()
                    else:
                        print(f"Invalid line format: {line.strip()}")
    except FileNotFoundError:
        print(f"File {Group_id_dir}{id}_group_id.txt not found")
    except ValueError as ve:
        print(f"Value error: {ve}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")




def send_message(target_ip, target_port, messagefirst, target_public_key ):
    global current_username, t2
    try:
        sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sender_socket.connect((target_ip, target_port))
        # message = f"first_message,{current_username},{messagefirst}"
        # print(message)
        EN_Message = encryptMessage(messagefirst, target_public_key)

        sender_socket.send(f"FIRST_MESSAGE,{current_username},{EN_Message}".encode())


        while True:
            message = input("(for the leav please write exit): ")
            EN_Message = encryptMessage(message, target_public_key)
            if message.lower() == 'exit':
                break
            sender_socket.send(EN_Message.encode())
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
                    print(f"\nis sign\n{sign}\n")
                    target_public_key = parts[2]
                    print(f"\nis target public key \n{target_public_key}\n")
                    target_port = parts[3]
                    print(f"\nis target port \n{target_port}\n")
                    # encrypted_key = bytes.fromhex(encrypted_key_hex.decode())
                    with open("server_public_key.pem", "rb") as f:
                        server_public_key = f.read()
                        print(server_public_key)
                    is_authentic = verify_sign(server_public_key, sign, target_public_key)
                    if is_authentic:
                        print("Message verify Succsefully.")
                        print(f"Content of Message: {target_public_key}")
                        peer_ip = 'localhost'
                        target_port = int(target_port)
                        message = input("enter the first message: ")
                        Private_Chat = 1
                        sender_thread = threading.Thread(target=send_message, args=(peer_ip, target_port, message, target_public_key))
                        sender_thread.start()
                    else:
                        print("Message Can't Veriy")
                    # print(f"Step 5: Decrypted public key: {decrypted_key.decode()}")
                    # Handle the decrypted key (use it to encrypt messages to the target user)
                else:
                    print("Invalid public key format.")
            
            elif message.startswith(b"group_chat_acctepted"):
                parts = message.split(b',', 3)
                role="admin"
                if len(parts) == 4:
                    id = parts[1]
                    sign = parts[2]
                    with open("server_public_key.pem", "rb") as f:
                        server_public_key = f.read()
                    peer_ip = 'localhost'
                    is_authentic1 = verify_sign(server_public_key, sign, id)
                    if is_authentic1:
                        if isinstance(id, bytes):
                            id = id.decode('utf-8')
                        with open(f"{Group_id_dir}{id}_group_id.txt", 'a') as f:
                            f.write(f"{current_username}: {Group_port}:{role}")
                        add_clientes(sign, id)
                        
                        message = input("enter the message: ")
                        # sender_group_thread = threading.Thread(target=send_group_message, args=(id, message))
                        # sender_group_thread.start()
                        print ( "2 is done")




            else:
                text_area.insert(tk.END, message.decode() + '\n')
        except Exception as e:
            print(f"An error occurred: {e}")
            client_socket.close()
            break


def add_clientes(sign, id):
    while True:
        
        user = input("Enter the username (enter done for finish):   ")
        if user == 'done':
            break

        target_ip = '127.0.0.1'
        #send the sign and id with private chat
        target_port= load_listen_port_client(user)
        print(target_port)
        message = f"add_my_group,{id},{sign}"
        pub_key = load_public_keys(user)
        sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        target_port = int(target_port)
        print("w")
        sender_socket.connect((target_ip, target_port))
        print("w")
        sender_socket.send(message.encode())
        print("w")
        sender_socket.close()

def load_listen_port_client(targert_username):
        listen_port=0
        with open('port.txt', "r") as f:
            for line in f:
                if line.strip():  # Skip empty lines
                    username, port= line.strip().split(',')
                    if username == targert_username:
                        listen_port = port
        return listen_port


def write(event=None):
    message = entry_message.get()
    if message:
        client_socket.send(message.encode())
        entry_message.delete(0, tk.END)

def on_closing():
    client_socket.close()
    root.destroy()


def encryptMessage(message, pub_key):
    public_key = serialization.load_pem_public_key(pub_key, backend=default_backend())
    
    if isinstance(message, str):
        message = message.encode()  # تبدیل رشته به بایت اگر لازم باشد
    
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_message).decode()  # کدگذاری و تبدیل به رشته


def decryptMessage(encrypted_message, private_key):
    try:
        # Decode base64-encoded message
        encrypted_message = base64.b64decode(encrypted_message)

        # Convert private_key to bytes if it's a string
        if isinstance(private_key, str):
            private_key = private_key.encode()

        # Load PEM-encoded private key
        private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())

        # Decrypt the message
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decode decrypted bytes to string
        return decrypted_message.decode()
    
    except Exception as e:
        print(f"Decryption error: {e}")
        return None


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


def load_keys(username):
    private_key = {}
    with open(f"{private_keys_dir}{username}_private_key.pem", "r") as f:
        private_key = f.read()
    return private_key


def load_public_keys(username):
    public_key = {}
    with open(f"{Publickey_keys_dir}{username}_public_key.pem", "r") as f:
        public_key = f.read()
    return public_key



def listen_for_messages_Group(Group_port):
    listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener_socket.bind(('localhost', Group_port))
    listener_socket.listen(2)
    print(f"Client is listening on port for Group chat {Group_port}...")

    while True:
        client_socket, addr = listener_socket.accept()
        print(f"New connection from {addr}")
        client_handler = threading.Thread(target=handle_incoming_messages, args=(client_socket,))
        client_handler.start()


#when request add is accepted from another user
def add_is_accepted(id , username):
    print("on the add accteped")
    global Group_port
    print (Group_port)
    role="member"
    # if isinstance(id, bytes):
    #     id = id.decode('utf-8')
    with open(f"{Group_id_dir}{id}_group_id.txt", 'a') as f:
            f.write(f"\n{username}: {Group_port}: {role}")
    sender_thread2 = threading.Thread(target=send_message_on_group,args=(id,))
    sender_thread2.start()

def request_remove_member_from_group():
    global current_username
    group_id = simpledialog.askstring("Remove Member", "Enter the Group ID:")
    member_to_remove = simpledialog.askstring("Remove Member", "Enter the username of the member to remove:")
    if group_id and member_to_remove:
        remove_member_from_group(group_id,member_to_remove)
        client_socket.send(f"REMOVE_MEMBER,{group_id},{member_to_remove},{current_username}".encode())
        print(f"Sent request to remove member {member_to_remove} from group {group_id}")

def remove_member_from_group(group_id, username_to_remove):
    role = ''
    try:
        with open(f"{Group_id_dir}{group_id}_group_id.txt", "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith(current_username):
                    if line.strip():  # Skip empty lines
                        parts = line.strip().split(':')
                        if len(parts) == 3:
                            username, port, role = parts
                            role = role.strip()
    except FileNotFoundError:
        print(f"File {Group_id_dir}{group_id}_group_id.txt not found.")
        return
    except ValueError as ve:
        print(f"Value error: {ve}")
        return
    print(role)
    if role == "admin":
        group_file_path = f"{Group_id_dir}{group_id}_group_id.txt"
        if os.path.exists(group_file_path):
            with open(group_file_path, 'r') as f:
                lines = f.readlines()
            with open(group_file_path, 'w') as f:
                for line in lines:
                    if username_to_remove not in line:
                        f.write(line)
            print(f"Member {username_to_remove} has been removed from the group {group_id}.")
        else:
            print(f"Group file {group_file_path} does not exist.")
    else:
        print("You do not have admin privileges to remove a member from the group.")

def request_promote_to_admin():
    global current_username
    group_id = simpledialog.askstring("promote Member", "Enter the Group ID:")
    member_to_promote = simpledialog.askstring("promote Member", "Enter the username of the member to remove:")
    if group_id and  member_to_promote:
        promote_member_to_admin(group_id, member_to_promote)
        client_socket.send(f"promote_MEMBER,{group_id},{ member_to_promote},{current_username}".encode())
        print(f"Sent request to promote member { member_to_promote} from group {group_id}")

def promote_member_to_admin(group_id, username_to_promote):
    role = ''
    group_file_path = f"{Group_id_dir}{group_id}_group_id.txt"
    
    if os.path.exists(group_file_path):
        with open(group_file_path, "r") as f:
            lines = f.readlines()
            for line in lines:
                if line.startswith(current_username):
                    if line.strip():  # Skip empty lines
                        parts = line.strip().split(':')
                        if len(parts) == 3:
                            username, port, role = parts
    
    print(role)
    if role == "admin":
        if os.path.exists(group_file_path):
            with open(group_file_path, 'r') as f:
                lines = f.readlines()
            with open(group_file_path, 'w') as f:
                for line in lines:
                    if line.startswith(username_to_promote):
                        parts = line.strip().split(':')
                        if len(parts) == 3:
                            username, port, role = parts
                            role = "admin"
                            f.write(f"{username}:{port}:{role}\n")
                    else:
                        f.write(line)
            print(f"Member {username_to_promote} has been promoted to admin in group {group_id}.")
        else:
            print(f"Group file {group_file_path} does not exist.")
    else:
        print("You do not have admin privileges to promote a member to admin.")

# تابعی برای مدیریت پیام‌های ورودی
def handle_incoming_messages(client_socket):
    
    global Private_Chat, current_username
    message = client_socket.recv(1024).decode()
    print(message)
    private_key = load_keys(current_username)
 
    if message.startswith("add_my_group"):
            print("its add")
            parts = message.split(',')
            if len(parts) == 3:
                id = parts[1]

                #have bug in the sign
                # sign = parts[2]
                # with open("server_public_key.pem", "rb") as f:
                #         server_public_key = f.read()
                # idE = id.encode('utf-8')
                # is_authentic1 = verify_sign(server_public_key, sign, idE)
                # if (is_authentic1):
                message = input(f"Do you want to add group with id({id})(y/n): ")
                if message == 'y':
                    add_is_accepted(id , current_username)
                    print(current_username)
                    print(message)
                else:
                    print("cant verify the message its not safe")
    elif message.startswith("its_group"):
        print("here")
        parts = message.split(',')
        #  message_for_send = f"its_group,{id},{sign},{message}"
        if len(parts) == 5:
            username = parts[1]
            id = parts[2]
            sign = parts[3]
            message = parts[4]
            pub_key = load_public_keys(username)
            is_auth = verify_sign(pub_key,sign,message)
            if (is_auth):
                print(f"{username}: {message}")
            else:
                print("cant verify the message unfortunatly")
                
    elif  decryptMessage(message, private_key).startswith("FIRST_MESSAGE") and Private_Chat == 0:
        parts = message.split(',')
        if len(parts) == 3:
            sender_username = parts[1]
            firstmessage = parts[2]
            print(DE_message)
            print(sender_username)
            print(f"Step 1: try for give the pub key from {sender_username}")
            request_chat2(sender_username)

 

    else:
        while True:
            try:
                message = client_socket.recv(1024).decode()
                private_key = load_keys(current_username)
                DE_message = decryptMessage(message, private_key)
                if not message:
                    break
                print(f"\nMessage Received: {DE_message}")
            except Exception as e:
                print(f"An error occurred: {e}")
                client_socket.close()
                break


def listen_for_messages(port):
    listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener_socket.bind(('localhost', port))
    listener_socket.listen(2)
    print(f"Client is listening on port {port}...")

    while True:
        client_socket, addr = listener_socket.accept()
        print(f"New connection from {addr}")
        client_handler = threading.Thread(target=handle_incoming_messages, args=(client_socket,))
        client_handler.start()


user_ports[current_username] = port_for_listen

with open('port.txt', 'w') as f:
    for username, port in user_ports.items():
        f.write(f"{username}, {port}\n")

print(f"Successfully saved port for listening: {port_for_listen} and username: {current_username}.")










Group_port = random.randint(1024, 65535)

def request_group_chat():
    global Group_port , current_username
    id = simpledialog.askstring("Request_Group_Chat", "Enter the Group ID: ")
    client_socket.send(f"REQUEST_Group_CHAT,{id},{Group_port},{current_username}".encode())
    print(f"Step 1: Sent Group chat request with id {id} and port {Group_port}")



# Start Thread for listening for Group messages
listener_thread = threading.Thread(target=listen_for_messages_Group, args=(Group_port,))
listener_thread.start()


# Start Thread for listening for messages
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

# Add Remove Member button
remove_member_button = tk.Button(root, text="Remove Member", command=request_remove_member_from_group)
remove_member_button.grid(row=5, column=0, columnspan=2, pady=10)

promote_button = tk.Button(root, text="Promote to Admin", command=request_promote_to_admin)
promote_button.grid(row=7, column=0, pady=10)
#Group Chat
request_chat_button = tk.Button(root, text="Request Group Chat", command=request_group_chat)
request_chat_button.grid(row=1, column=0, columnspan=2, pady=15)

# Start the thread for receiving messages
receive_thread = threading.Thread(target=receive, args=(client_socket,))
receive_thread.start()

# Start the tkinter main loop
root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
