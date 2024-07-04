import socket

# تنظیمات سرور
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)

print("سرور آماده برای اتصال است...")

while True:
    conn, addr = server_socket.accept()
    print(f"اتصال از {addr} برقرار شد.")

    # دریافت پیام از کلاینت
    message = conn.recv(1024).decode()
    if message:
        print(f"پیام کلاینت: {message}")
    
    # ارسال پاسخ به کلاینت
    response = input("پاسخ به کلاینت: ")
    conn.send(response.encode())

    conn.close()

server_socket.close()
