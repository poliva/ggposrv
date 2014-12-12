#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# UDP Hole Punching wrapper proxy for ggpofba-ng
#
#  (c) 2014 Pau Oliva Fora (@pof)
#  (c) 2010 Koen Bollen <meneer koenbollen nl>
#  (C) 2009 Dmitriy Samovskiy, http://somic.org
#   https://gist.github.com/koenbollen/464613
#   https://gist.github.com/somic/224795
#
# puncher function License: Apache License, Version 2.0
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import sys
import os
import socket
from select import select
from subprocess import Popen, PIPE
import struct
import random
import threading
import Queue
import time
import traceback
import logging
import platform

def bytes2addr( bytes ):
	"""Convert a hash to an address pair."""
	if len(bytes) != 6:
		raise ValueError, "invalid bytes"
	host = socket.inet_ntoa( bytes[:4] )
	port, = struct.unpack( "H", bytes[-2:] )
	return host, port


def start_fba(args):

	FBA="ggpofba-ng.exe"

	# try to guess install directory:
	dirtest = os.path.abspath(os.path.dirname(sys.argv[0]))
	if not os.path.isfile(os.path.join(dirtest,FBA)):
		dirtest = os.path.dirname(os.path.abspath(__file__))
	if not os.path.isfile(os.path.join(dirtest,FBA)):
		dirtest = os.getcwd()
	if not os.path.isfile(os.path.join(dirtest,FBA)):
		print >>sys.stderr, "Can't find", FBA
		logging.info("Can't find %s" % FBA)
		os._exit(1)

	FBA=os.path.join(dirtest,FBA)

	# try to find wine
	wine="/Applications/Wine.app/Contents/Resources/bin/wine"
	if not os.path.isfile(wine):
		wine="/usr/bin/wine"
	if not os.path.isfile(wine):
		wine='/usr/local/bin/wine'
	if not os.path.isfile(wine):
		wine=os.path.join(dirtest,"../Resources/bin/wine")
	if not os.path.isfile(wine):
		# assume we are on windows
		args.insert(0, FBA)
	else:
		args.insert(0, FBA)
		args.insert(0, wine)

	try:
		logging.debug("RUNNING %s" % args)
		p = Popen(args)
	except OSError:
		print >>sys.stderr, "Can't execute", FBA
		logging.info("Can't execute %s" % FBA)
		os._exit(1)
	return p

def puncher(sock, remote_host, port):
# License: Apache License, Version 2.0
#          http://www.apache.org/licenses/
#
	my_token = str(random.random())
	logging.debug("my_token = %s" % my_token)
	remote_token = "_"

	sock.setblocking(0)
	sock.settimeout(5)

	remote_knows_our_token = False

	for i in range(10):
		r,w,x = select([sock], [sock], [], 0)

		if remote_token != "_" and remote_knows_our_token:
			logging.debug("we are done - hole was punched from both ends")
			break

		if r:
			data, addr = sock.recvfrom(1024)
			if addr[0]==remote_host and addr[1]!=port:
				logging.info("remote end uses symmetric or restricted nat. Changing port from %d to %d." % (port, addr[1]))
				port=addr[1]
			logging.debug("recv: %r" % data)
			if remote_token == "_":
				remote_token = data.split()[0]
				logging.debug("remote_token is now %s" % remote_token)
			if len(data.split()) == 3:
				logging.debug("remote end signals it knows our token")
				remote_knows_our_token = True

		if w:
			data = "%s %s" % (my_token, remote_token)
			if remote_token != "_": data += " ok"
			logging.debug("sending: %r" % data)
			sock.sendto(data, (remote_host, port))
			logging.debug("sent %d" % i)
		time.sleep(0.5)

	logging.debug("puncher done")

	return remote_token != "_", port


def udp_proxy(args,q):

	master = ("fightcade.com", 7000)
	l_sockfd = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
	bindok=0
	try:
		port=7001
		l_sockfd.bind(("127.0.0.1", port))
	except socket.error:
		logging.info("Can't bind to port 7001, using system assigned port.")
		l_sockfd.sendto("", ("127.0.0.1", 7001))
		bindaddr,port=l_sockfd.getsockname()
		bindok+=1

	logging.info("listening on 127.0.0.1:%d (udp)" % port)

	#use only the challenge id for the hole punching server
	quark = args[0].split(",")[2]

	sockfd = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
	# bind the socket to a port, so we can test the user's NAT type
	try:
		sockfd.bind(("0.0.0.0", 21112))
	except socket.error:
		# kill any existing instances of ggpofba here
		logging.info("Can't bind to port 21112, using system assigned port.")
		bindok+=1

	if bindok>=2:
		logging.info("Another instance of ggpofba seems to be running. Killing ggpofba.")
		l_sockfd.close()
		sockfd.close()
		killGgpoFba()
		os._exit(1)

	sockfd.sendto( quark+"/"+str(port), master )
	try:
		data, addr = sockfd.recvfrom( len(quark)+3 )
		logging.debug("request received from %s = %r" % (addr, data))
	except:
		logging.info("Error receiving request from master. Using ports.")
		sockfd.sendto( "useports/"+quark, master)
		fba_pid=start_fba(args)
		q.put(fba_pid)
		return

	if data != "ok "+quark:
		print >>sys.stderr, "unable to request!"
		logging.info("unable to request!")
		#os._exit(1)
	sockfd.sendto( "ok", master )
	logging.info("request sent, waiting for partner in quark '%s'..." % quark)
	sockfd.settimeout(25)
	try:
		data, addr = sockfd.recvfrom( 6 )
	except socket.timeout:
		logging.info("timeout waiting for peer's address. Using ports.")
		sockfd.sendto( "useports/"+quark, master)
		fba_pid=start_fba(args)
		q.put(fba_pid)
		return
	except socket.errror:
		logging.info("error getting peer address. Using ports.")
		sockfd.sendto( "useports/"+quark, master)
		fba_pid=start_fba(args)
		q.put(fba_pid)
		return

	target = bytes2addr(data)
	logging.debug("connected to %s:%d" % target)

	punch_ok, port = puncher(sockfd, target[0], target[1])
	logging.info ("Puncher result: %s" % punch_ok)

	restricted_nat=False
	if not punch_ok:
		# try to punch the hole using a new ip:port mapping that has never reached another destination
		n_sockfd = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
		try:
			logging.info("Listening on 0.0.0.0:6004/udp")
			n_sockfd.bind(("0.0.0.0", 6004))
		except socket.error:
			logging.info("Error listening on 0.0.0.0:6004/udp")
		punch_ok, port = puncher(n_sockfd, target[0], 6004)
		restricted_nat=True

	if not punch_ok:
		# tell the server that this quark must use ports
		logging.info("Puncher failed. Using ports.")
		sockfd.sendto( "useports/"+quark, master)

	if restricted_nat:
		sockfd.close()
		sockfd=n_sockfd

	if port!=target[1]:
		logging.info("Changing remote port from %d to %d." % (target[1], port))
		target = (target[0], port)

	fba_pid=start_fba(args)
	q.put(fba_pid)

	if not punch_ok:
		return

	# first request using blocking sockets:
	l_sockfd.settimeout(25)
	try:
		emudata, emuaddr = l_sockfd.recvfrom(16384)
		logging.debug("first request from emulator at %s = %r" % (emuaddr, emudata))
	except socket.timeout:
		logging.info("timeout waiting for emulator")
		emuaddr = ('127.0.0.1', 6000)
		emudata=''

	if emudata:
		logging.debug("sending data to target %s = %r" % (target, emudata))
		sockfd.sendto( emudata, target )

	try:
		peerdata, peeraddr = sockfd.recvfrom(16384)
		logging.debug("first request from peer at %s = %r" % (peeraddr, peerdata))
		logging.debug("peer %s , target %s" % (peeraddr, target))
		if peerdata and " _" in peerdata:
			peerdata, peeraddr = sockfd.recvfrom(16384)
			logging.debug("request from peer at %s = %r" % (peeraddr, peerdata))
		if peerdata and " ok" in peerdata:
			peerdata, peeraddr = sockfd.recvfrom(16384)
			logging.debug("request from peer at %s = %r" % (peeraddr, peerdata))
		if peerdata and " ok" not in peerdata and " _" not in peerdata:
			logging.debug("sending data to emulator %s = %r" % (emuaddr, peerdata))
			l_sockfd.sendto( peerdata, emuaddr )
	except:
		logging.info("timeout waiting for peer")

	logging.info("received first request")

	# now continue the game using nonblocking:
	l_sockfd.setblocking(0)
	sockfd.setblocking(0)

	logging.info("setting nonblocking sockets")

	while True:
		try:
			rfds,_,_ = select( [sockfd,l_sockfd], [], [], 0.1)
			if l_sockfd in rfds:
				emudata, emuaddr = l_sockfd.recvfrom(16384)
				if emudata:
					sockfd.sendto( emudata, target )
			if sockfd in rfds:
				peerdata, peeraddr = sockfd.recvfrom(16384)
				if peerdata:
					l_sockfd.sendto( peerdata, emuaddr )
		except:
			logging.info("exit loop")
			sockfd.close()
			l_sockfd.close()
			os._exit(0)

def killGgpoFba():
	if platform.system()=="Windows":
		try:
			args = ['taskkill', '/f', '/im', 'ggpofba.exe']
			Popen(args, shell=True)
			args = ['tskill', 'ggpofba', '/a']
			Popen(args, shell=True)
		except:
			pass
	else:
		try:
			args = ['pkill', '-f', 'ggpofba.*quark:served']
			devnull = open(os.devnull, 'w')
			Popen(args, stdout=devnull, stderr=devnull)
			devnull.close()
		except:
			pass


def registerUriHandler():

	from _winreg import CreateKey, SetValueEx, HKEY_CURRENT_USER, REG_SZ, CloseKey
	regKeys = []
	regKeys.append(['Software\\Classes\\fightcade', '', 'URL:fightcade Protocol'])
	regKeys.append(['Software\\Classes\\fightcade', 'URL Protocol', ""])
	regKeys.append(['Software\\Classes\\fightcade\\shell', '', None])
	regKeys.append(['Software\\Classes\\fightcade\\shell\\open', '',  None])

	for key,name,val in regKeys:
		registryKey = CreateKey(HKEY_CURRENT_USER, key)
		SetValueEx(registryKey, name, 0, REG_SZ, val)
		CloseKey(registryKey)

	regKeysU = []
	regKeysU.append(['Software\\Classes\\fightcade\\shell\\open\\command',  '', os.path.abspath(sys.argv[0])+' "%1"'])
	for key,name,val in regKeysU:
		registryKey = CreateKey(HKEY_CURRENT_USER, key)
		SetValueEx(registryKey, name, 0, REG_SZ, val)
		CloseKey(registryKey)

def process_checker(q):

	time.sleep(15)
	fba_p=q.get()
	logging.debug("FBA pid: %d" % int(fba_p.pid))

	while True:
		time.sleep(5)
		fba_status=fba_p.poll()
		#print "FBA STATUS:", str(fba_status)
		#logging.debug("FBA STATUS: %s" % str(fba_status))
		if fba_status!=None:
			logging.info("killing process")
			os._exit(0)

def main():

	args = sys.argv[1:]
	logging.debug("args: %s" % args)

	quark=''
	if len(args)>0:
		quark=args[0]

	if platform.system()=="Windows":
		registerUriHandler()

	if quark.startswith('quark:served'):
		q = Queue.Queue()
		t = threading.Thread(target=process_checker, args=(q,))
		t.setDaemon(True)
		t.start()
		udp_proxy(args,q)
		t.join()
	elif quark.startswith('fightcade://challenge-'):
		try:
			quarkid=quark.split('/')[2].split('@')[0]
			game=quark.split('/')[2].split('@')[1]
			args=['quark:stream,'+game+','+quarkid+',7000', '-w']
		except:
			pass
		start_fba(args)
	elif quark.startswith('challenge-'):
		try:
			quarkid=quark.split('@')[0]
			game=quark.split('@')[1]
			args=['quark:stream,'+game+','+quarkid+',7000', '-w']
		except:
			pass
		start_fba(args)
	else:
		start_fba(args)

if __name__ == "__main__":

	log = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "ggpofba.log")
	errorlog = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "ggpofba-errors.log")

	try:
		#loglevel=logging.DEBUG
		loglevel=logging.INFO
		logging.basicConfig(filename=log, filemode='w', level=loglevel, format='%(asctime)s:%(levelname)s:%(message)s')

		main()
	except:
		traceback.print_exc(file=open(errorlog,"w"))
		os._exit(1)
