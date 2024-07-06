import socket
import threading

PORT = 12345  # پورت مشترک برای همه نودها
peers = []  # لیست نودهای همتا

def listen_for_messages(local_socket):
    while True:
        try:
            message, addr = local_socket.recvfrom(1024)
            if addr not in peers:
                peers.append(addr)  # اضافه کردن نود جدید به لیست نودها
            print(f"\nMessage from {addr}: {message.decode('utf-8')}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def send_message(message, local_socket):
    for peer in peers:
        try:
            local_socket.sendto(message.encode('utf-8'), peer)
        except Exception as e:
            print(f"Failed to send message to {peer}: {e}")

def main():
    local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_socket.bind(('0.0.0.0', PORT))

    # اجرای رشته‌ای برای دریافت پیام‌ها
    receive_thread = threading.Thread(target=listen_for_messages, args=(local_socket,))
    receive_thread.start()

    print("Enter peers in the format <IP>:<PORT> (e.g., 127.0.0.1:12345). Type 'done' when finished.")
    while True:
        peer = input("Enter peer: ")
        if peer.lower() == 'done':
            break
        ip, port = peer.split(':')
        peers.append((ip, int(port)))

    while True:
        message = input("Enter message: ")
        send_message(message, local_socket)

if __name__ == "__main__":
    main()
