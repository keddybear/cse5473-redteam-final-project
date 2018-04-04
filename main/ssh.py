import binascii

# SSH
# =====
# This class parses SSH payload

class SSH:

	TAG = "SSH: "

	def __init__ (self, payload):
		if len(payload) % 2 != 0 or len(payload) < 6:
			raise Exception(SSH.TAG + "__init__: Payload length error: " + str(len(payload)))
			return
		#endif
		if payload[0:2] == "SSH":
			raise Exception(SSH.TAG + "__init__: Payload: " + payload)
			return
		#endif
		self.packet_len = int(binascii.hexlify(payload[0:4]), 16)
		self.padding_len = int(binascii.hexlify(payload[4:5]), 16)
		self.SSH_MSG_KEXINIT = payload[5:6]

		if (self.to_hex(self.SSH_MSG_KEXINIT) == "14"):
			# Algorithm negotiation
			self.cookie = payload[6:22]
			kex_algorithms_len = int(binascii.hexlify(payload[22:26]), 16)
			self.kex_algorithms = payload[26:26+kex_algorithms_len]
			self.rest = payload[26+kex_algorithms_len:-self.padding_len]
		elif (self.to_hex(self.SSH_MSG_KEXINIT) == "22"):
			# DH key exchange
			# TODO
			pass
		#endif
	#enddef

	def reconstruct (self):
		if self.to_hex(self.SSH_MSG_KEXINIT) == "14":
			payload = self.SSH_MSG_KEXINIT + self.cookie + binascii.unhexlify("{0:0{1}x}".format(len(self.kex_algorithms),8)) + self.kex_algorithms + self.rest
			padding_len = self.get_padlen(len(payload))
			packet_len = 1 + len(payload) + padding_len
			packet = binascii.unhexlify("{0:0{1}x}".format(packet_len,8)) + binascii.unhexlify("{0:02x}".format(padding_len)) + payload + chr(0) * padding_len
			return packet
		else:
			return None
		#endif
	#enddef

	def to_hex (self, ch):
		return "{0:02x}".format(ord(ch))
	#enddef

	def get_padlen (self, payload_len):
		for x in range(4,256):
			if (4 + 1 + payload_len + x) % 8 == 0:
				return x
			#endif
		#endfor
	#enddef

#endclass