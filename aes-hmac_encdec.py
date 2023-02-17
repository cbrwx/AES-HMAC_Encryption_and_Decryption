# Import necessary modules
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Define constants
SALT_SIZE = 16
ITERATIONS = 200000

# Function to encrypt plaintext using AES and return ciphertext, initialization vector (IV), salt and HMAC
def aes_encrypt(plaintext, password):
    # Generate salt and derive key using password and salt
    salt = os.urandom(SALT_SIZE)
    kdf = PBKDF2HMAC(algorithm=algorithms.SHA256(), length=32, salt=salt, iterations=ITERATIONS, backend=default_backend())
    key = kdf.derive(password.encode())

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

# Function to decrypt ciphertext using AES and return plaintext
def aes_decrypt(ciphertext, password, iv, salt, mac):
    # Decode ciphertext, derive key using password and salt, and verify HMAC
    decoded_ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
    kdf = PBKDF2HMAC(algorithm=algorithms.SHA256(), length=32, salt=salt, iterations=ITERATIONS, backend=default_backend())
    key = kdf.derive(password.encode())
    h = hmac.HMAC(key, algorithms.SHA256(), backend=default_backend())
    h.update(ciphertext.encode())
    h.verify(mac)

    # Decrypt ciphertext and unpad plaintext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(decoded_ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()
