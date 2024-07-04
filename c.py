import socket
import threading
import random

# تابعی برای گوش دادن به پیام‌های ورودی
def listen_for_messages(port):
    listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener_socket.bind(('localhost', port))
    listener_socket.listen(5)
    print(f"کلاینت در پورت {port} منتظر اتصال است...")

    while True:
        client_socket, addr = listener_socket.accept()
        print(f"اتصال جدید از {addr}")
        client_handler = threading.Thread(target=handle_incoming_messages, args=(client_socket,))
        client_handler.start()

# تابعی برای مدیریت پیام‌های ورودی
def handle_incoming_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if not message:
                break
            print(f"\nپیام دریافتی: {message}")
        except:
            client_socket.close()
            break

# تابعی برای ارسال پیام به یک کلاینت دیگر
def send_message(target_ip, target_port):
    try:
        sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sender_socket.connect((target_ip, target_port))
        while True:
            message = input("پیام به کلاینت دیگر (یا 'exit' برای خروج): ")
            if message.lower() == 'exit':
                break
            sender_socket.send(message.encode())
        sender_socket.close()
    except Exception as e:
        print(f"خطا در ارسال پیام به {target_ip}:{target_port} - {e}")

# تولید پورت رندوم در محدوده پورت‌های مجاز (1024-65535)
port = random.randint(1024, 65535)
print(f"پورت رندوم تولید شده برای کلاینت: {port}")

# راه‌اندازی ترد برای گوش دادن به پیام‌های ورودی
listener_thread = threading.Thread(target=listen_for_messages, args=(port,))
listener_thread.start()

# دریافت اطلاعات کلاینت‌های دیگر برای ارسال پیام
peers = []
while True:
    peer_ip = input("آدرس IP کلاینت دیگر (یا 'done' برای اتمام): ")
    if peer_ip.lower() == 'done':
        break
    peer_port = int(input("پورت کلاینت دیگر: "))
    peers.append((peer_ip, peer_port))

# راه‌اندازی ترد برای ارسال پیام به کلاینت‌های دیگر
for peer_ip, peer_port in peers:
    sender_thread = threading.Thread(target=send_message, args=(peer_ip, peer_port))
    sender_thread.start()
