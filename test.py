from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def encryptMessage(message, key):
    public_key = serialization.load_pem_public_key(key, backend=default_backend())
    
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
    return encrypted_message

def decryptMessage(encrypted_message, private_key):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

# کلید عمومی
pub = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAudoOfPfNTIR0W4kncfP1
jrAhbmAdWxgARK/A0OVP8yuiMr6ZUcZdPkm79eXeWniS8FzeBH1yFOAZQ5KAWG0J
iz91bze59znyKesQLe3OGVCBHmDqt5YS2dBUc5P8de1qft7EN9Bb8rcgXFEn6FzI
ZagrgWvVPcmZ13y7s1rbpJZu0PxIFO3do9ia1t8FU7FJyUwX6VU0vMNFkM+gFYnp
thSBEmBMtyURIpg7sdYkmtaf4AcgvQgPLNgV4gZnMKqfH0SbUWPunX0TQHTo+BxS
k2Gt95zy/kCIx+cP0ZMSnMVtanBrkJRu0xNXORh0ZMINHxGpP8I1XE2mjR4rB7l+
qQIDAQAB
-----END PUBLIC KEY-----"""

# کلید خصوصی
private_key_pem = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC52g58981MhHRb
iSdx8/WOsCFuYB1bGABEr8DQ5U/zK6IyvplRxl0+Sbv15d5aeJLwXN4EfXIU4BlD
koBYbQmLP3VvN7n3OfIp6xAt7c4ZUIEeYOq3lhLZ0FRzk/x17Wp+3sQ30FvytyBc
USfoXMhlqCuBa9U9yZnXfLuzWtuklm7Q/EgU7d2j2JrW3wVTsUnJTBfpVTS8w0WQ
z6AViem2FIESYEy3JREimDux1iSa1p/gByC9CA8s2BXiBmcwqp8fRJtRY+6dfRNA
dOj4HFKTYa33nPL+QIjH5w/RkxKcxW1qcGuQlG7TE1c5GHRkwg0fEak/wjVcTaaN
HisHuX6pAgMBAAECggEAAU8oQ6MZ6XcUEW0BlSDrKD/UtyAANPBnWBSGNDKEAf+F
sKZ9EqwQuMFGN1uQ2cGjBK8ddUSjoBgFYDTQ/fkj/xIfCVMy1oCsVF/uiOmgRmIL
IXlR+KHFrOPLJIFKCalMKGv4pTgCMySCcC62LEHdu4btajJQmeh9/UbzVOEdTlHU
iIAl0pSqpLE2YVSXoey14aJJkaOyB/OXO0wUOpmoTZ78Tw4QKo0JRmzhrTgDgjLj
F9B6Kc512QJRwTMT48o4GQTA3LXjI+KEQ1wUCscXz2z4K3extQ2s67N2PqSu8RTf
v/LaMijuixN0on+aMC8RcLtNcTaHD72Dl9Bpx/MH8QKBgQD6S7b2obKxI3NnLlMB
htjnPc0A/Dxsd8tO+mX+EjqIr9PAoAHSF3Dvo3gqe9pz7IaO9aSNS8C2ePBYtNft
sec0oTqz+y8xPSWJY5wdkp8zCgti8ZCrShn4qYrwhpaFoswwRPKA4+7s20Wp7L1b
EPahk5kl/kDFFp26Lr5C6t+ndQKBgQC+Flw+YKk2d/kIGvoDg3Waurilefs0x6xy
rPmzAtGO5QHC08HMiTndZ7+12HE2kf9/+9AybikKQZU/YlKnOTQ6rCVTZPJ3Q7KU
1jAvSd+AGo6F7ejhEvHmC0tVBbZbkgMg9vLWtIYQqII9IJpNYp/SbO4oZk4WG5hD
nWaZubKH5QKBgGlBfeepiCPF7LnvWSjDNGPKMXPAnwheODk2Q73cnJDun/XZU+qt
wOiFrfrvqqYlSVDFLDXfLWOO6EPliQiET95qDu2xK99g/3APW490IU6tYqxxOY1O
1C0l3y/W6WW5WHTUCcb6E3e3nkwfKmIpeA3qq/S2PzailCG/lnM9omAhAoGAb8rY
vzq76bPPOwwag5x5uuEbnP5LVfQkoGDIjZYXxrE6Qumk7XS7GlJc9kZv9scQe6WO
AUq2Sjjd3KQntf83j1YUsaIJ00h2K4B4YCdTEZUMwwlzT4ODzmZQDJXKdLo/qtBx
awJKYluoFOkqtl5NXkUAH7RjMi9SclmMsNX8gF0CgYEAsfvvqHWEje8gNtTxiKFc
/GyCxkSClrVbc8CXlDo7WXidzmK0FLfJ1ujfxpYm30Fzq5mJbFfOpPW/ke+IVdaG
fCF3+f90rWD0pKydQFwou04Iycs2ykoYdTEVsD77qq+P9rSKR8hlRC4c5xryRkEs
iIf06mhb8ZFMj9JKJiQjdMM=
-----END PRIVATE KEY-----"""

message2 = b"salam vaght bekheir"
message3 = encryptMessage(message2, pub)

print(message2)
# فراخوانی تابع رمزگشایی
decrypted_message = decryptMessage(message3, private_key_pem)
print(decrypted_message)
