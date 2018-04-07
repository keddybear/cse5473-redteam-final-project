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
			# Cookie
			self.cookie = payload[6:22]
			# Key exchange algorithms
			kex_algorithms_len = int(binascii.hexlify(payload[22:26]), 16)
			self.kex_algorithms = payload[26:26+kex_algorithms_len]
			rest = payload[26+kex_algorithms_len:]
			# Host key algorithms
			pub_key_algorithms_len = int(binascii.hexlify(rest[0:4]), 16)
			self.pub_key_algorithms = rest[4:4+pub_key_algorithms_len]
			rest = rest[4+pub_key_algorithms_len:]
			# Symmetric key algorithms
				# client to host (ch)
			sym_key_algorithms_ch_len = int(binascii.hexlify(rest[0:4]), 16)
			self.sym_key_algorithms_ch = rest[4:4+sym_key_algorithms_ch_len]
			rest = rest[4+sym_key_algorithms_ch_len:]
				# host to client (hc)
			sym_key_algorithms_hc_len = int(binascii.hexlify(rest[0:4]), 16)
			self.sym_key_algorithms_hc = rest[4:4+sym_key_algorithms_hc_len]
			rest = rest[4+sym_key_algorithms_hc_len:]
			# MAC algorithms
				# client to host (ch)
			mac_algorithms_ch_len = int(binascii.hexlify(rest[0:4]), 16)
			self.mac_algorithms_ch = rest[4:4+mac_algorithms_ch_len]
			rest = rest[4+mac_algorithms_ch_len:]
				# host to client (hc)
			mac_algorithms_hc_len = int(binascii.hexlify(rest[0:4]), 16)
			self.mac_algorithms_hc = rest[4:4+mac_algorithms_hc_len]
			rest = rest[4+mac_algorithms_hc_len:]
			# rest
			self.rest = rest[0:-self.padding_len]
		elif (self.to_hex(self.SSH_MSG_KEXINIT) == "22"):
			# DH key exchange
			# TODO
			pass
		#endif
	#enddef

	def reconstruct (self):
		if self.to_hex(self.SSH_MSG_KEXINIT) == "14":
			# Code + Cookie
			payload = self.SSH_MSG_KEXINIT + self.cookie
			# Key exchange
			payload = payload + self.len_to_hex(self.kex_algorithms) + self.kex_algorithms
			# Host key
			payload = payload + self.len_to_hex(self.pub_key_algorithms) + self.pub_key_algorithms
			# Symmetric key
			payload = payload + self.len_to_hex(self.sym_key_algorithms_ch) + self.sym_key_algorithms_ch
			payload = payload + self.len_to_hex(self.sym_key_algorithms_hc) + self.sym_key_algorithms_hc
			# MAC
			payload = payload + self.len_to_hex(self.mac_algorithms_ch) + self.mac_algorithms_ch
			payload = payload + self.len_to_hex(self.mac_algorithms_hc) + self.mac_algorithms_hc
			# rest
			payload = payload + self.rest
			# Padding
			padding_len = self.get_padlen(len(payload))
			# Packet len
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

	def len_to_hex (self, s):
		# A quick way to turn length number into 4 bytes
		return binascii.unhexlify("{0:0{1}x}".format(len(s),8))
	#enddef

	def get_padlen (self, payload_len):
		for x in range(4,256):
			if (4 + 1 + payload_len + x) % 8 == 0:
				return x
			#endif
		#endfor
	#enddef

#endclass