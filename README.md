# Introduction
This is the final project for CSE 5473 Network Security, at the Ohio State University.
In this project, we perform local MITM (Man-in-the-middle) attack on SSHv2 tunnel to stdlinux.cse.ohio-state.edu, for educational purposes.

**Systems:**
- Victim: Ubuntu 16.04
- Attacker: Kali Linux
  
**Proramming Lanugage:**
- Python 2.7.14

**Libraries:**
- scapy
- pycryptodome
- sshpubkey

The SSHv2 tunnel to stdlinux.cse.ohio-state.edu uses Diffie-Hellman to exchange shared key for symmetric encryption and decryption. “diffie-hellman-group-exchange-sha256” is used as the exchange method. The negotiated algorithms are ssh-rsa, aes128-ctr, and umac-64@openssh.com, by default. Our MITM can successfully establish a shared key with the server. However, the client will run into **ssh_dispatch_run_fatal: error in libcryto**, after the user answers “yes” during RSA key verification. The decryption of packets using shared keys is yet to be implemented.

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
