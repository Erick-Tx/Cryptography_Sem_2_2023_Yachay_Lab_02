from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

import hashlib
import binascii

def decrypt(ciphertext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode, default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data

def unpad(data, size=128):
    padder = padding.PKCS7(size).unpadder()
    unpadded_data = padder.update(data)
    unpadded_data += padder.finalize()
    return unpadded_data

def main():
    ciphertext_hex = input("Enter the ciphertext in hexadecimal format: ")
    password = input("Enter the decryption key: ")
    
    ciphertext = bytes.fromhex(ciphertext_hex)
    key = hashlib.sha256(password.encode()).digest()

    decrypted_data = decrypt(ciphertext, key, modes.ECB())
    plaintext = unpad(decrypted_data)
    
    print("Decrypted text:", plaintext.decode())

if __name__ == "__main__":
    main()
