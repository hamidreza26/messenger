from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import os

# تولید کلید خصوصی و عمومی
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# تابع رمزنگاری با استفاده از کلید خصوصی
def encrypt_with_private_key(private_key, message):
    # تولید یک کلید تصادفی برای AES
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()

    # رمزنگاری کلید AES با استفاده از کلید خصوصی
    encrypted_key = private_key.decrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key, iv, encrypted_message

# تابع رمزگشایی با استفاده از کلید عمومی
def decrypt_with_public_key(public_key, encrypted_key, iv, encrypted_message):
    # رمزگشایی کلید AES با استفاده از کلید عمومی
    aes_key = public_key.encrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # رمزگشایی پیام با استفاده از AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode()

# پیام برای رمزنگاری
message = "This is a secret message."

# رمزنگاری پیام با کلید خصوصی
try:
    encrypted_key, iv, encrypted_message = encrypt_with_private_key(private_key, message)
    print("Encrypted message:", encrypted_message)
except Exception as e:
    print(f"Error in encryption: {e}")

# رمزگشایی پیام با کلید عمومی
try:
    decrypted_message = decrypt_with_public_key(public_key, encrypted_key, iv, encrypted_message)
    print("Decrypted message:", decrypted_message)
except Exception as e:
    print(f"Error in decryption: {e}")
