"""
This file is an example of how to generate keys with RSA and encrypt.

"""

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import binascii

# Generate an RSA key
rsa_key = RSA.generate(2048, e=65537)
public_key = rsa_key.publickey().exportKey("PEM") 
private_key = rsa_key.exportKey("PEM") 
session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
message = "Hello, world!"
data = message.encode()
cipher_rsa = PKCS1_OAEP.new(rsa_key)
ciphertext_rsa = cipher_rsa.encrypt(data)

print(binascii.hexlify(ciphertext_rsa))

# Decrypt the message with RSA
decrypted_message = cipher_rsa.decrypt(ciphertext_rsa).decode()
print("\n# Decrypted text")
print("Message: " + message)
print("Decrypt: " + decrypted_message)


# Encrypt the data with the AES session key
# cipher_aes = AES.new(session_key, AES.MODE_EAX)
# ciphertext, tag = cipher_aes.encrypt_and_digest(data)
#[ file_out.write(x) for x in (cipher_aes.nonce, tag, ciphertext) ]
