import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import base64

HOST = 'localhost'
PORT = 5009

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

p2p_socket = None
root = tk.Tk()

def verify_sign(public_key_pem, encrypted_message, original_message):
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
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
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def receive(client_socket):
    while True:
        try:
            message = client_socket.recv(1024)
            if message.startswith(b"public key is here"):
                handle_public_key_message(message)
            elif message.startswith(b"P2P_INFO"):
                handle_p2p_info(message.decode())
            else:
                text_area.insert(tk.END, message.decode() + '\n')
        except Exception as e:
            print(f"An error occurred: {e}")
            client_socket.close()
            break

def handle_public_key_message(message):
    print("Step 4: Received encrypted public key from server.")
    parts = message.split(b',', 2)
    if len(parts) == 3:
        sign = parts[1]
        target_public_key = parts[2]
        with open("server_public_key.pem", "rb") as f:
            server_public_key = f.read()
        is_authentic = verify_sign(server_public_key, sign, target_public_key)
        if is_authentic:
            print("پیام اصیل است و توسط سرور ارسال شده است.")
            print(f"محتوای پیام: {target_public_key}")
        else:
            print("پیام اصیل نیست یا توسط سرور ارسال نشده است.")
    else:
        print("Invalid public key format.")

def on_closing():
    global p2p_socket
    client_socket.close()
    if p2p_socket:
        p2p_socket.close()
    root.destroy()

def login_or_register():
    while True:
        action = simpledialog.askstring("Action", "Do you want to 'login' or 'register'?")
        if action == 'login':
            username = simpledialog.askstring("Login", "Enter your username:")
            password = simpledialog.askstring("Login", "Enter your password:", show='*')
            client_socket.send(f"LOGIN,{username},{password}".encode())
            response = client_socket.recv(1024).decode()
            if response == "Login successful.":
                messagebox.showinfo("Info", "Login successful.")
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
    if target:
        client_socket.send(f"REQUEST_CHAT,{target}".encode())
        print(f"Step 1: Sent chat request to {target}")
        client_socket.send(f"REQUEST_P2P_CHAT,{target}".encode())        


def handle_p2p_info(message):
    global p2p_socket
    parts = message.split(',')
    if len(parts) == 3:
        p2p_ip = parts[1]
        p2p_port = int(parts[2])
        p2p_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        p2p_socket.connect((p2p_ip, p2p_port))
        threading.Thread(target=receive_p2p).start()
        print(f"Connected to P2P peer at {p2p_ip}:{p2p_port}")

def receive_p2p():
    while True:
        try:
            message = p2p_socket.recv(1024).decode()
            if message:
                text_area.insert(tk.END, "Peer: " + message + '\n')
            else:
                break
        except Exception as e:
            print(f"P2P connection error: {e}")
            break

def write_p2p(event=None):
    message = entry_message.get()
    if message and p2p_socket:
        p2p_socket.send(message.encode())
        text_area.insert(tk.END, "You: " + message + '\n')
        entry_message.delete(0, tk.END)
    else:
        messagebox.showerror("Error", "Not connected to any peer.")


login_or_register()

# Text display area
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=40, height=20)
text_area.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

# Entry for typing messages
entry_message = tk.Entry(root, width=30)
entry_message.grid(row=1, column=0, padx=10, pady=10)

# Bind the Enter key to the write function
entry_message.bind("<Return>", write_p2p)

# Send button
send_button = tk.Button(root, text="Send", command=write_p2p)
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
