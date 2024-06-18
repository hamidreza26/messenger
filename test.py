import threading
import time

from server import Server
from Client import ClientGUI

# Start the server in a separate thread
server_thread = threading.Thread(target=lambda: Server('localhost', 9000).start())
server_thread.start()

# Wait for the server to start
time.sleep(1)

# Create multiple client instances
clients = [
    ClientGUI('localhost', 9000),
    ClientGUI('localhost', 9000),
    ClientGUI('localhost', 9000),
]

# Connect the clients to the server
for client in clients:
    threading.Thread(target=client.connect).start()

# Simulate sending messages from different clients
def simulate_chatting():
    clients[0].message_entry.insert(0, "Hello from Client 1!")
    clients[0].send_message()
    time.sleep(1)

    clients[1].message_entry.insert(0, "Hi, Client 1!")
    clients[1].send_message()
    time.sleep(1)

    clients[2].message_entry.insert(0, "Hey, everyone!")
    clients[2].send_message()
    time.sleep(1)

    clients[0].message_entry.insert(0, "Nice to meet you!")
    clients[0].send_message()
    time.sleep(1)

    clients[1].message_entry.insert(0, "Likewise!")
    clients[1].send_message()
    time.sleep(1)

    clients[2].message_entry.insert(0, "What's up?")
    clients[2].send_message()
    time.sleep(1)

    clients[0].message_entry.insert(0, "Just chilling!")
    clients[0].send_message()
    time.sleep(1)

    clients[1].message_entry.insert(0, "Same here!")
    clients[1].send_message()

# Simulate chatting after a delay
threading.Thread(target=simulate_chatting).start()

# Wait for the simulated chat to finish
time.sleep(10)

# Disconnect the clients
for client in clients:
    client.disconnect()

# Stop the server
Server('localhost', 9000).stop()

# Wait for the server to stop
server_thread.join()