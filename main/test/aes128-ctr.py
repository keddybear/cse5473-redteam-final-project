from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

secret = os.urandom(16)
key = "7842f0a1ebc38f44e3e0c81943f68582"
# crypto = AES.new(os.urandom(32), AES.MODE_CTR, counter=lambda: secret)
# encrypted = crypto.encrypt("Hello world!")

# print crypto.decrypt(encrypted)

print repr(int_to_hex(2783837534,2))