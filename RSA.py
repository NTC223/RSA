import hashlib
import random
from Crypto.Util.number import getPrime

class RSA:
    def __init__(self, bits=1024):
        self.__p = getPrime(bits)
        self.__q = getPrime(bits)
        self.n = self.__p * self.__q
        self.__phi = (self.__p - 1) * (self.__q - 1)

        # Chọn kích thước cho e để giảm thời gian chạy
        e_size = bits // 8 if bits > 64 else ((bits + 8) % 16)

        while True:
            self.e = getPrime(e_size)
            if self.__gcd_extended(self.e, self.__phi)[0] == 1:
                break

        self.__d = self.__modulo_inverse(self.e, self.__phi)

    # Euclid mở rộng
    def __gcd_extended(self, a, b):
        if a == 0:
            return b, 0, 1
        gcd, y, x = self.__gcd_extended(b % a, a)
        return gcd, x - (b // a) * y, y

    # Nghịch đảo modulo
    def __modulo_inverse(self, e, phi):
        gcd, x, y = self.__gcd_extended(e, phi)
        if gcd != 1:
            raise Exception("No modular inverse")
        return x % phi

    # Băm file bằng SHA-1
    def hash_file(self, message):
        if isinstance(message, str):
            message = message.encode()
        h = hashlib.sha1()
        h.update(message)
        return h.hexdigest()

    # Hàm ký
    def sign(self, m):
        hashed = int(self.hash_file(m), 16)
        return pow(hashed, self.__d, self.n)

    # Hàm kiểm tra chữ ký
    def verify(self, m, signature):
        hashed = int(self.hash_file(m), 16)
        return pow(signature, self.e, self.n) == hashed

rsa = RSA(512)

message = "Hello, this is a test message."
signature = rsa.sign(message)
print("Message:", message)
print("Signature:", signature)
print("Verification:", rsa.verify(message, signature))