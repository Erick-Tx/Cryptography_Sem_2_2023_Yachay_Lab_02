from Crypto.Cipher import AES
import base64
import hashlib
from Crypto.Util.Padding import unpad

def decrypt_text(ciphertext_base64, password):
    try:
        key = hashlib.sha256(password.encode()).digest()
        print("Texto key:", key)
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext_bytes = base64.b64decode(ciphertext_base64)
        decrypted_data = cipher.decrypt(ciphertext_bytes)
        plaintext = unpad(decrypted_data, AES.block_size)
        return plaintext.decode('utf-8')
    except Exception as e:
        print("Error during decryption:", str(e))
        return None

# Ejemplo de uso
ciphertext_base64 = input("Introduce el texto cifrado en formato base64: ")
password = input("Introduce la contraseña: ")

plaintext = decrypt_text(ciphertext_base64, password)
if plaintext:
    print("Texto descifrado:", plaintext)