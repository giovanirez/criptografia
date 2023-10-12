import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class AesHelper():
    def __init__(self, key=None, iv=None):
        if key is None:
            self.key = os.urandom(32)
        else:
            self.key = key
        if iv is None:
            self.iv = os.urandom(16)
        else:
            self.iv = iv
        self.cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv))

    def encrypt(self, message):
        message = base64.b64encode(message.encode()).decode()
        padding_length = 16 - (len(message) % 16)
        message += " " * padding_length
        encryptor = self.cipher.encryptor()
        return encryptor.update(message.encode("utf-8")) + encryptor.finalize()

    def decrypt(self, message):
        decryptor = self.cipher.decryptor()
        decrypted_message = decryptor.update(message) + decryptor.finalize()
        decrypted_message = decrypted_message.rstrip(b' ')
        return base64.b64decode(decrypted_message).decode("utf-8")

aes = AesHelper()
p1 =input(str('Digite o texto a ser criptografado: ')) 
criptografado = aes.encrypt(p1)
descriptografado = aes.decrypt(criptografado)

print("Criptografada: ", criptografado)
print("Descriptografada: ", descriptografado)
