from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def signMessage(message, private_key):
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),  # یا از padding.PSS استفاده کنید
        hashes.SHA256()
    )
    return signature



def verifySignature(message, signature, public_key):
    public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),  # یا از padding.PSS استفاده کنید
            hashes.SHA256()
        )
        return "Verification succeeded"  # تایید موفقیت آمیز
    except Exception as e:
        return f"Verification failed: {str(e)}"  # تایید ناموفق





# کلید عمومی\
pub = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqm+Hxh+9DroJAoDCVxSB
r5TE/gWOE+mp+0wXzyrzHDcqfxxY7tHgjkqQ547XkDOTiMKPQCED4EOMVj4vdmUw
tWl1jugh2Dy401TEwQ4tpXtwvG4ZXNO+jtaNIiGYKALxgMk4FDYKpHqRoysyD24/
5BBGu0mFRf6Pu876YVH7DnVQsGjdkMk1Uber6pI9rdspYosKDpag3yy7jPanPRje
j7+ZLYM4fdcL3495mOW1paGWNwiq0lALx41WPPTLqrn3Lu6R8tQhmp6hxYwb/JCp
/05kMvfaAGmSQXgjkERGjNo8SZ6PA2s2RQLv51KEMLYH3VFEHh7CHsHFmrsJRSut
jQIDAQAB
-----END PUBLIC KEY-----"""

# کلید خصوصی
private_key_pem = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqb4fGH70OugkC
gMJXFIGvlMT+BY4T6an7TBfPKvMcNyp/HFju0eCOSpDnjteQM5OIwo9AIQPgQ4xW
Pi92ZTC1aXWO6CHYPLjTVMTBDi2le3C8bhlc076O1o0iIZgoAvGAyTgUNgqkepGj
KzIPbj/kEEa7SYVF/o+7zvphUfsOdVCwaN2QyTVRt6vqkj2t2yliiwoOlqDfLLuM
9qc9GN6Pv5ktgzh91wvfj3mY5bWloZY3CKrSUAvHjVY89Muqufcu7pHy1CGanqHF
jBv8kKn/TmQy99oAaZJBeCOQREaM2jxJno8DazZFAu/nUoQwtgfdUUQeHsIewcWa
uwlFK62NAgMBAAECggEAC0re+d1V+zEP0kLiPX9OFWpbwAHxtzeK6+vPgwozN+oe
znO8H7y3rm3Z2oHQHg2Qx6WudJ8LYPNQy9EMd4F+X/K4F4shXPCvBU+PRsRP+XAr
mMyJsSkVbeTgzoNfz7zcL/6FEO/AtkOpvSAqTbPuF0gNy7B0HF5gux6cX9Dc+8jl
1TcipAQRBxtJ2ktUbMSXZ0FIAbvGhGijjna1WXnE8XN7ZyaUU9mylmjRGBcwumEI
J/u0gaDe53JGEG8cC111hiZEgucDddCAR/iCgaHoAxs/TZZARHGxlD0Xi+xE8PXN
4TzERsaTcJUQ4etwRSeJQMmm+ZWnsAZKsCxvgXpmCQKBgQDirxsjy/5VsPtEW+5S
Q5f8FeKE/N9CgAr6zRCbHG0GmHQP1JLTpw0K/nIpu839SPH3ZqgxlJIrOa+rPRzm
LoLKGz4HuMt7egc5Kg2nAzun5NAzGg30rDc6qaWXDaM7ayg6D747UahUWk1nllO+
q0dDT9jr33JHFLQjwvNbf8bbiQKBgQDAejGoErg2JlcXedF28UjXYXVvH0JqV+4Y
WgH5T1elIh2xQKZ+jDz8OvQpJmbkvJ72nNuaXosC5FBWBHJF4Q8T/CJnOfz0UAYE
uThNFQRRpgpR4uv/URqRI0HTVG73/Kvmx6Bb+aMIpC7hRDoktt0YC007kE4MEwBA
YGb+6e/s5QKBgDVl5lDCZwEslaP+u98pCQ5a4WdOYhE6NFvsHnNLeOtK0lxASO4O
teXXFnF6SgXWPxl2VzyGsP/5sMX3uW0Hm8ucKzqKb3SAxF7U5y5mdpEQN3MyOgNe
5gutltJEZiVDEtDKkJdMnwhv1TgHk2ag1kKm9oRpuHPCDsU10TnGmcNxAoGAXbwk
aqGTLGvHhhtBMxeWTa2crx0eDwP7Y8iRpYRKPpU6uJOvgXlySbO8LD4TZdml4JvL
JoZcVHAz33AS5o0P9r+XUYYf9iryg2JgVMmjbM/bvr0wCQrKUVxGNlCsKgDXBnC5
W5FbIF40pme/mRmk2ozGc/d2ytKGENPh1MrAmTECgYEAuxQI//jft+YwwPRrFnWj
v4Vnl7Q/+AjlhFwro26k5ovzziDIvmduwqkFu396ax6o87PCDkkcKpARdOGrBYQ3
GzV5cPsrq9nn5GU5hoTZ0QByQtq8VfssvuYMo60saC3JOz+aHdOYeaf3u7bAJ+ZM
qfzkWR/M868f4cBg0vCxxnw=
-----END PRIVATE KEY-----"""

message = "salam vaght bekheir"
signature = signMessage(message, private_key_pem)

# تایید امضا
result = verifySignature(message, signature, pub)
print(result)