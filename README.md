# Introduction
This is the final project for CSE 5473 Network Security, at the Ohio State University.
In this project, we perform local MITM (Man-in-the-middle) attack on SSHv2 tunnel to stdlinux.cse.ohio-state.edu, for educational purposes.

**Systems:**
- Victim: Ubuntu 16.04
  - Victim IP: 10.0.2.4
  - Gateway IP: 10.0.2.2
  
**Proramming Lanugage:**
- Python 2.7.14

**Libraries:**
- scapy
- pycryptodome
- sshpubkey

The SSHv2 tunnel to stdlinux.cse.ohio-state.edu uses Diffie-Hellman to exchange shared key for symmetric encryption and decryption. “diffie-hellman-group-exchange-sha256” is used as the exchange method. The negotiated algorithms are ssh-rsa, aes128-ctr, and umac-64@openssh.com, by default.
Our MITM can successfully establish shared keys with both the client and server, but the decryption of packets using shared keys is yet to be implemented.

## Install Scapy
http://scapy.readthedocs.io/en/latest/installation.html

## Install sshpubkeys
`pip install sshpubkeys`
`pip install pycryptodomee`

## Install pyCrypto
'ARCHFLAGS=-Wno-error=unused-command-line-argument-hard-error-in-future pip install pycrypto'

## Instructions
* Run mitm.py
* Run sniffer.py
