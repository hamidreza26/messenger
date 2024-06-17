import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

HOST = 'localhost'
PORT = 5004
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
socket_lock = threading.Lock()

def receive(client_socket):
    while True:
        try:
            message = client_socket.recv(1024)
            if message.startswith(b"public key is here"):
                print("Step 4: Received encrypted public key from server.")
                parts = message.split(b',', 1)
                if len(parts) == 2:
                    encrypted_key_hex = parts[1]
                    encrypted_key = bytes.fromhex(encrypted_key_hex.decode())
                    with open("server_public_key.pem", "rb") as f:
                        server_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
                    decrypted_key = server_public_key.decrypt(
                        encrypted_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    print(f"Step 5: Decrypted public key: {decrypted_key.decode()}")
                    # Handle the decrypted key (use it to encrypt messages to the target user)
                else:
                    print("Invalid public key format.")
            else:
                text_area.insert(tk.END, message.decode() + '\n')
        except Exception as e:
            print(f"An error occurred in receive thread: {e}")
            client_socket.close()
            break

def write(event=None):
    message = entry_message.get()
    if message:
        try:
            with socket_lock:
                client_socket.send(message.encode())
            entry_message.delete(0, tk.END)
        except Exception as e:
            print(f"An error occurred while sending message: {e}")
            client_socket.close()

def on_closing():
    try:
        with socket_lock:
            client_socket.close()
    except Exception as e:
        print(f"An error occurred while closing the socket: {e}")
    root.destroy()

def login_or_register():
    while True:
        action = simpledialog.askstring("Action", "Do you want to 'login' or 'register'?")
        if action == 'login':
            username = simpledialog.askstring("Login", "Enter your username:")
            password = simpledialog.askstring("Login", "Enter your password:", show='*')
            try:
                with socket_lock:
                    client_socket.send(f"LOGIN,{username},{password}".encode())
                response = client_socket.recv(1024).decode()
                if response == "Login successful.":
                    messagebox.showinfo("Info", "Login successful.")
                    break
                else:
                    messagebox.showerror("Error", response)
            except Exception as e:
                print(f"An error occurred during login: {e}")
                client_socket.close()
                break
        elif action == 'register':
            username = simpledialog.askstring("Register", "Enter your username:")
            password = simpledialog.askstring("Register", "Enter your password:", show='*')
            try:
                with socket_lock:
                    client_socket.send(f"REGISTER,{username},{password}".encode())
                response = client_socket.recv(1024).decode()
                if response == "Registration successful.":
                    messagebox.showinfo("Info", "Registration successful. Please login now.")
                else:
                    messagebox.showerror("Error", response)
            except Exception as e:
                print(f"An error occurred during registration: {e}")
                client_socket.close()
                break
        else:
            messagebox.showerror("Error", "Invalid action. Please type 'login' or 'register'.")

def request_chat():
    target = simpledialog.askstring("Request Chat", "Enter the recipient's username:")
    try:
        with socket_lock:
            client_socket.send(f"REQUEST_CHAT,{target}".encode())
        print(f"Step 1: Sent chat request to {target}")
    except Exception as e:
        print(f"An error occurred while requesting chat: {e}")
        client_socket.close()

root = tk.Tk()
root.title("Simple Messenger")

login_or_register()

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
