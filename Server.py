import socket
import threading
import hashlib
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
HOST = 'localhost'
PORT = 5003

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()

clients = {}
users_db = "users.txt"
Publickey_keys_dir = "public_keys/"
private_keys_dir = "private_keys/"
Group_id_dir = "Group_id_dir/"
if not os.path.exists(Publickey_keys_dir):
    os.makedirs(Publickey_keys_dir)

if not os.path.exists(Group_id_dir):
    os.makedirs(Group_id_dir)


if not os.path.exists(private_keys_dir):
    os.makedirs(private_keys_dir)


# Generate server's RSA key pair
def generate_rsa_key():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
    private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
    return private_key_pem

# Save server's public key to a file
# def save_public_key(public_key, filename="server_public_key.pem"):
#     with open(filename, "wb") as f:
#         f.write('b"""/n')
#         f.write(public_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ))
#         f.write('"""')
def save_public_key_server(public_key, filename="server_public_key.pem"):
    with open(filename, "wb") as f:
        f.write(public_key)


# Generate and save the server's key pair
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
server_private_key_pem = server_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
server_public_key = server_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
save_public_key_server(server_public_key)

def load_users():
    users = {}
    with open(users_db, "r") as f:
            for line in f:
                if line.strip():  # Skip empty lines
                    username, password_hash, salt = line.strip().split(',')
                    users[username] = (password_hash, salt)
    # except FileNotFoundError:
    #     pass
    print(users)
    return users

def save_user(username, password_hash, salt):
    with open(users_db, "a") as f:
        f.write(f"{username},{password_hash},{salt}\n")




def save_public_key(username, public_key_pem):
    with open(f"{Publickey_keys_dir}{username}_public_key.pem", "wb") as f:
        f.write(public_key_pem)


def load_keys(username):
    public_key = {}
    with open(f"{Publickey_keys_dir}{username}_public_key.pem", "r") as f:
        public_key = f.read()
        # public_key = serialization.load_pem_public_key(key.encode(), backend=default_backend())
    return public_key


from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import base64

def sign_server(private_key_pem, message):
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



# original_message = b"""
# -----BEGIN PUBLIC KEY-----
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5bX/G1XqVSBUWoEX3CfL
# xXdVZ6jtJ37tZN17dhPLVSVLKrammFNGWysmuGCrpnES3tnaMPJu/u/f/0FU/Tqo
# daCorUCkmLdE2oGdXtwgk7WrI2UR/6O11BoAlUtOyKIGItMY+TrZ/bC+MdcdPF59
# naNOH8UyS1eglVa3rMYiRfcdIy6CDtvkuzEJLGVzmRvyMADv9psUt7Dd3hF7d0zH
# jND0QPTbIU7zyqOKcUbs2CG6413Fnr2hQ8/kH3RNCNQ//q/M6iZccPBbj4ThECbO
# ljNt/vbRwl16xJOyDTGpriWD+mjoWPwfeqCmSaml4s/D41aVpGlbxj3TanWCyjcR
# JwIDAQAB
# -----END PUBLIC KEY-----
# """



# encrypted_message = sign_server(server_private_key_pem, original_message)
# # print(f"\n\n encrypt message \n {encrypted_message}")

# # کلاینت: رمزگشایی و بررسی اصالت پیام
# is_authentic = verify_sign(server_public_key, encrypted_message, original_message)
# if is_authentic:
#     print("پیام اصیل است و توسط سرور ارسال شده است.")
#     print(f"محتوای پیام: {original_message}")
# else:
#     print("پیام اصیل نیست یا توسط سرور ارسال نشده است.")

# # آزمایش با پیام تغییر یافته
# altered_message = "این یک پیام تغییر یافته است."
# is_authentic = verify_sign(server_public_key, encrypted_message, altered_message)
# if is_authentic:
#     print("پیام تغییر یافته اصیل است.")
# else:
#     print("پیام تغییر یافته اصیل نیست.")



#load the port of clients the they listen on that
def load_listen_port_client(targert_username):
        with open('port.txt', "r") as f:
            for line in f:
                if line.strip():  # Skip empty lines
                    username, port= line.strip().split(',')
                    if username == targert_username:
                        listen_port = port
        return listen_port



def save_private_key(username, private_key):
    with open(f"{private_keys_dir}{username}_private_key.pem", "wb") as f:
        f.write(private_key)
        # print('private is fuckedup')

def generate_keys():
    # private_key = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048,
    #     backend=default_backend()
    # )
    # public_key = private_key.public_key()

    # private_key_pem = private_key.private_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PrivateFormat.PKCS8,
    #     encryption_algorithm=serialization.NoEncryption()
    # )

    # public_key_pem = public_key.public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # )
    server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
    server_private_key_pem = server_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    server_public_key = server_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return server_private_key_pem, server_public_key

def handle_client(client_socket, address):
    user = None
    while True:
        try:
            data = client_socket.recv(1024).decode()
            if data.startswith("REGISTER"):
                print(data)
                print('\n')
                _, username, password = data.split(',')
                salt = os.urandom(16).hex()
                password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
                users = load_users()
                if username in users:
                    client_socket.send("Username already exists.".encode())
                else:
                    save_user(username, password_hash, salt)
                    private_key_pem, public_key_pem = generate_keys()
                    save_private_key(username, private_key_pem)
                    save_public_key(username, public_key_pem)
                    client_socket.send("Registration successful.".encode())
                    
            elif data.startswith("LOGIN"):
                _, username, password = data.split(',')
                users = load_users()
                if username in users:
                    stored_hash, salt = users[username]
                    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
                    if stored_hash == password_hash:
                        client_socket.send("Login successful.".encode())
                        user = username
                        break
                    else:
                        client_socket.send("Invalid username or password.".encode())
                else:
                    client_socket.send("Invalid username or password.".encode())
        except Exception as e:
            print(f"Error during registration/login: {e}")
            client_socket.close()
            return

    clients[user] = client_socket
    print(f"{user} joined from {address}")

    while True:
        try:
            print('enter the request of private chat\n')
            message = client_socket.recv(1024).decode()
            if message.startswith("REQUEST_CHAT"):
                parts = message.split(',')
                if len(parts) == 2:
                    _, target_user = parts
                    print(f"Received chat request for {target_user} from {user}")
                    keys = None
                    keys = load_keys(target_user)
                    print(keys)
                    if keys != None:
                        target_public_key = keys
                        # # Encrypt the public key with server public key
                        sign = sign_server(server_private_key_pem,target_public_key)
                        print (f"\nis sign\n{sign}\n")
                        print (f"\nis target public key \n{target_public_key}\n")
                        port_target = load_listen_port_client(target_user)
                        message = f"public key is here,{sign},{target_public_key},{port_target}"
                        print(f"Sending encrypted public key to {user}")
                        client_socket.send(message.encode())

                    else:
                        client_socket.send("User not found.".encode())
                else:
                    print("Invalid REQUEST_CHAT format.")

            elif message.startswith("REQUEST_Group_CHAT"):
                    print("request on the server ")
                    print(message)
                    parts = message.split(',', 3)
                    if len(parts) == 4:
                        id = parts[1]
                        username = parts[3]

                        if not os.path.exists(f"{Group_id_dir}{id}_group_id.txt"):
                            pass
                            with open(f"{Group_id_dir}{id}_group_id.txt", 'w') as f:
                                print(f"{Group_id_dir}{id}_group_id.txt created.")
                        else:
                            print("this id is already exists!")
                            return 0

                        sign = sign_server(server_private_key_pem,id)
                        message = f"group_chat_acctepted,{id},{sign},{username}"
                        print(f" step 1 is done {id}\n {username}")                        
                        client_socket.send(message.encode())



            elif message.startswith("SEND"):
                parts = message.split(',', 2)
                if len(parts) == 3:
                    _, recipient, enc_message = parts
                    send_message(f"FROM,{user},{enc_message}".encode(), recipient)
                else:
                    print("Invalid SEND format.")
            else:
                send_message(message.encode(), user)
        except Exception as e:
            print(f"Error during message handling: {e}")
            if user in clients:
                del clients[user]
                client_socket.close()
            print(f"Connection closed with {address} - username: {user}")
            break

def send_message(message, recipient):
    if recipient in clients:
        try:
            clients[recipient].send(message)
        except Exception as e:
            print(f"Error sending message to {recipient}: {e}")
            del clients[recipient]
    else:
        print(f"User {recipient} is not connected.")

def accept_clients():
    while True:
        try:
            client_socket, address = server_socket.accept()
            print(f"New connection from {address}")
            thread = threading.Thread(target=handle_client, args=(client_socket, address))
            thread.start()
        except Exception as e:
            print(f"Error accepting clients: {e}")

print("Server started!")
accept_thread = threading.Thread(target=accept_clients)
accept_thread.start()