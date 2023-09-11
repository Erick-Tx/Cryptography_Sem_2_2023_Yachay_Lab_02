from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import sys
import binascii

# Verificar si se proporcionan el número correcto de argumentos de línea de comandos
if len(sys.argv) < 3:
    print("Uso: python cipher01.py <texto_plano> <clave>")
    sys.exit(1)

# Extraer el texto plano y la clave de los argumentos de línea de comandos
texto_plano = sys.argv[1]
clave = sys.argv[2]

def encrypt(plaintext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode, default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return ct

def pad(data, size=128):
    padder = padding.PKCS7(size).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data

# Generar una clave AES a partir de la clave proporcionada usando el hash SHA-256
key = hashlib.sha256(clave.encode()).digest()

print("Antes del relleno:", texto_plano)

texto_plano = pad(texto_plano.encode())

print("Después del relleno (CMS):", binascii.hexlify(bytearray(texto_plano)))

ciphertext = encrypt(texto_plano, key, modes.ECB())
print("Cifrado (ECB):", binascii.hexlify(bytearray(ciphertext)))
