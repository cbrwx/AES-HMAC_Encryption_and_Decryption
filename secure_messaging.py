# Import the aes_encrypt and aes_decrypt functions from the aes_hmac module
from aes_hmac import aes_encrypt, aes_decrypt

# Define plaintext and password to be encrypted
plaintext = "secret delicious message"
password = "password" 

# Encrypt the plaintext using the aes_encrypt function
encrypted_data = aes_encrypt(plaintext, password)
# Extract the ciphertext, initialization vector (IV), salt and HMAC from the encrypted_data
ciphertext, iv, salt, mac = encrypted_data 

# Decrypt the ciphertext using the aes_decrypt function
decrypted_data = aes_decrypt(ciphertext, password, iv, salt, mac) 
# Set plaintext variable to the decrypted plaintext
plaintext = decrypted_data
