# AES Encryption and Decryption
This Python library provides a simple and secure way to encrypt and decrypt data using the AES algorithm with HMAC authentication.

# Features
- Uses the AES-CBC mode of operation for encryption and decryption
- Employs Argon2 password hashing for key derivation
- Applies PKCS7 padding to the plaintext before encryption
- Generates a secure HMAC to authenticate the ciphertext
- Provides error handling and constant-time HMAC comparison to mitigate side-channel attacks
# Installation
You will need Python 3.x and the cryptography package. You can install the cryptography package using pip:

```
pip install cryptography
```
# Usage
Import the aes_encrypt and aes_decrypt functions from the library:

```
from aes_encryption import aes_encrypt, aes_decrypt
```
# Encryption
To encrypt a plaintext, pass it along with a password to the aes_encrypt function:

```
plaintext = "This is a secret message."
password = "This is a strong password."

ciphertext, iv, salt, mac = aes_encrypt(plaintext, password)
```
This will return a tuple containing the encoded ciphertext, initialization vector (IV), salt, and HMAC.

# Decryption
To decrypt a ciphertext, pass it along with the password, IV, salt, and HMAC to the aes_decrypt function:

```
decrypted_plaintext = aes_decrypt(ciphertext, password, iv, salt, mac)
```
This will return the decrypted plaintext as a string.

# Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
