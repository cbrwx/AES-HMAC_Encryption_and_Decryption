import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hmac
from cryptography.hazmat.primitives.kdf.argon2 import PasswordHasher
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Define constants
SALT_SIZE = 16

# Function to encrypt plaintext using AES and return ciphertext, initialization vector (IV), salt and HMAC
def aes_encrypt(plaintext, password):
    try:
        if not isinstance(plaintext, str) or not isinstance(password, str):
            raise ValueError("Both plaintext and password must be strings.")

        # Generate salt and derive key using password and salt
        salt = os.urandom(SALT_SIZE)
        ph = PasswordHasher()
        key = ph.hash(password.encode())

        # Pad plaintext and encrypt using AES-CBC with IV
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
        iv = os.urandom(algorithms.AES.block_size // 8)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Encode ciphertext to base64 and generate HMAC
        encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        h = hmac.HMAC(key, algorithms.SHA256(), backend=default_backend())
        h.update(encoded_ciphertext.encode())
        mac = h.finalize()

        return encoded_ciphertext, iv, salt, mac
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

# Function to decrypt ciphertext using AES and return plaintext
def aes_decrypt(ciphertext, password, iv, salt, mac):
    try:
        if not isinstance(ciphertext, str) or not isinstance(password, str):
            raise ValueError("Both ciphertext and password must be strings.")

        # Decode ciphertext, derive key using password and salt, and verify HMAC
        decoded_ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        ph = PasswordHasher()
        key = ph.hash(password.encode())
        h = hmac.HMAC(key, algorithms.SHA256(), backend=default_backend())
        h.update(ciphertext.encode())

        # Verify HMAC using constant-time comparison
        try:
            h.verify(mac)
        except InvalidSignature:
            print("HMAC verification failed.")
            return None

        # Decrypt ciphertext and unpad plaintext
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(decoded_ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None
