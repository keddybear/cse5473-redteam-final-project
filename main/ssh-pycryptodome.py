from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import binascii

recipient_key = RSA.generate(2048, e=65537)
session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
message = "Hello, world!"
data = message.encode()
cipher_rsa = PKCS1_OAEP.new(recipient_key)
ciphertext_rsa = cipher_rsa.encrypt(data)
print(binascii.hexlify(ciphertext_rsa))

# Encrypt the data with the AES session key
# cipher_aes = AES.new(session_key, AES.MODE_EAX)
# ciphertext, tag = cipher_aes.encrypt_and_digest(data)
#[ file_out.write(x) for x in (cipher_aes.nonce, tag, ciphertext) ]
