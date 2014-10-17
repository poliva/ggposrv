#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# UDP Hole Punching wrapper proxy for ggpofba-ng
#
#  (c) 2014 Pau Oliva Fora (@pof)
#  (c) 2010 Koen Bollen <meneer koenbollen nl>
#   https://gist.github.com/koenbollen/464613
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

if os.name=='posix':
	import errno
else:
	import ctypes

# http://stackoverflow.com/a/23409343/1576221
def pid_exists(pid):
	"""Check whether pid exists in the current process table."""
	if os.name == 'posix':
		if pid < 0:
			return False
		try:
			os.kill(pid, 0)
		except OSError as e:
			return e.errno == errno.EPERM
		else:
			return True
	else:
		kernel32 = ctypes.windll.kernel32
		HANDLE = ctypes.c_void_p
		DWORD = ctypes.c_ulong
		LPDWORD = ctypes.POINTER(DWORD)
		class ExitCodeProcess(ctypes.Structure):
			_fields_ = [ ('hProcess', HANDLE),
				('lpExitCode', LPDWORD)]

		SYNCHRONIZE = 0x100000
		process = kernel32.OpenProcess(SYNCHRONIZE, 0, pid)
		if not process:
			return False

		ec = ExitCodeProcess()
		out = kernel32.GetExitCodeProcess(process, ctypes.byref(ec))
		if not out:
			err = kernel32.GetLastError()
			if kernel32.GetLastError() == 5:
				# Access is denied.
				logging.warning("Access is denied to get pid info.")
			kernel32.CloseHandle(process)
			return False
		elif bool(ec.lpExitCode):
			# print ec.lpExitCode.contents
			# There is an exist code, it quit
			kernel32.CloseHandle(process)
			return False
		# No exit code, it's running.
		kernel32.CloseHandle(process)
		return True

def bytes2addr( bytes ):
	"""Convert a hash to an address pair."""
	if len(bytes) != 6:
		raise ValueError, "invalid bytes"
	host = socket.inet_ntoa( bytes[:4] )
	port, = struct.unpack( "H", bytes[-2:] )
	return host, port


def start_fba(quark):

	FBA="ggpofba-ng.exe"

	if not os.path.isfile(FBA):
		print >>sys.stderr, "Can't find", FBA
		sys.exit(1)

	# try to find wine
	wine="/Applications/Wine.app/Contents/Resources/bin/wine"
	if not os.path.isfile(wine):
		wine="/usr/bin/wine"
	if not os.path.isfile(wine):
		wine='/usr/local/bin/wine'
	if not os.path.isfile(wine):
		# assume we are on windows
		args=[FBA, quark]
	else:
		args=[wine, FBA, quark]

	try:
		p = Popen(args)
	except OSError:
		print >>sys.stderr, "Can't execute", FBA
		sys.exit(1)
	return p

def main():
	master = ("g.x90.es", 7000)

	quark=''
	try:
		quark = sys.argv[1].strip()
	except (IndexError, ValueError):
		pass

	if quark.startswith('quark:served'):

		port = 7001
		l_sockfd = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
		l_sockfd.bind( ("", port) )
		#print "listening on *:%d (udp)" % port

		p=start_fba(quark)

		#use only the challenge id for the hole punching server
		quark = quark.split(",")[2]

		emudata, emuaddr = l_sockfd.recvfrom(0)
		#print "connection from %s:%d" % emuaddr

		sockfd = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
		sockfd.sendto( quark, master )
		data, addr = sockfd.recvfrom( len(quark)+3 )
		if data != "ok "+quark:
			print >>sys.stderr, "unable to request!"
			sys.exit(1)
		sockfd.sendto( "ok", master )
		print >>sys.stderr, "request sent, waiting for partner in quark '%s'..." % quark
		data, addr = sockfd.recvfrom( 6 )

		target = bytes2addr(data)
		#print >>sys.stderr, "connected to %s:%d" % target

		l_sockfd.setblocking(0)
		sockfd.setblocking(0)

		while pid_exists(p.pid):

			rfds,_,_ = select( [sockfd,l_sockfd], [], [], 0.1)
			if l_sockfd in rfds:
				emudata, emuaddr = l_sockfd.recvfrom(16384)
				if emudata:
					sockfd.sendto( emudata, target )
			if sockfd in rfds:
				peerdata, peeraddr = sockfd.recvfrom(16384)
				if peerdata:
					l_sockfd.sendto( peerdata, emuaddr )

		sockfd.close()
		l_sockfd.close()
		sys.exit(0)

	else:
		start_fba(quark)

if __name__ == "__main__":
	main()
