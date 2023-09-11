from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Generate a 256-bit (32-byte) AES key
def generate_aes_key():
    return get_random_bytes(32)  # 256 bits

# Pad plaintext to a 128-bit block size using CMS padding
def pad_data(plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(plaintext.encode(), AES.block_size)
    return padded_data

# Unpad plaintext after decryption
def unpad_data(ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(ciphertext, AES.block_size)
    return plaintext.decode()

# Encrypt plaintext using AES ECB mode
def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

# Decrypt ciphertext using AES ECB mode
def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Main program
if __name__ == "__main__":
    key = generate_aes_key()

    plaintext = "Your plaintext message"
    print("Original plaintext:", plaintext)

    # Pad and encrypt
    padded_data = pad_data(plaintext)
    ciphertext = encrypt(padded_data, key)
    print("Encrypted ciphertext:", ciphertext)

    # Decrypt and unpad
    decrypted_data = decrypt(ciphertext, key)
    original_plaintext = unpad_data(decrypted_data)
    print("Decrypted plaintext:", original_plaintext)
