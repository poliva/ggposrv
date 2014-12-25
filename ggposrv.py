#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# open source ggpo server (re)implementation
#
#  (c) 2014 Pau Oliva Fora (@pof)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# ggposrv.py includes portions of code borrowed from hircd.
# hircd is Copyright by Ferry Boender, 2009-2013
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#

import sys
import optparse
import logging
import ConfigParser
import os
import SocketServer
import socket
import select
import re
import struct
import time
import datetime
import random
import hmac
import hashlib
import sqlite3
import json
import gzip
import traceback
import threading
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer
try:
	# http://dev.maxmind.com/geoip/geoip2/geolite2/
	import geoip2.database
	reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
	pass

VERSION=19

MIN_CLIENT_VERSION=34

class GGPOHttpHandler(BaseHTTPRequestHandler):

	def print_dump(self):

		path = self.path
		out={}

		if path == "/channels":
			for channel in ggposerver.channels.values():
				out[channel.name]=[]
				for client in channel.clients:
					out[channel.name].append(client.nick)

		if path == "/clients":
			for client in ggposerver.clients.values():
				cli={}
				cli["status"]=client.status
				cli["channel"]=client.channel.name
				cli["quark"]=client.quark
				#cli["city"]=client.city
				cli["country"]=client.country
				cli["cc"]=client.cc
				cli["version"]=client.version
				out[client.nick]=cli

		if path == "/games":
			for quark in ggposerver.quarks.values():
				if quark.p1!=None and quark.p2!=None and quark.p1.nick!=None and quark.p2.nick!=None and quark.channel!=None:
					game={}
					game["channel"]=quark.channel.name
					game["p1"]=quark.p1.nick
					game["p2"]=quark.p2.nick
					game["spectators"]=len(quark.spectators)
					game["useports"]=quark.useports
					out[quark.quark]=game

		if path == "/stats":
			out["version"]='{0:.2f}'.format(VERSION/100.0)
			clients = len(ggposerver.clients)
			out["clients"]=clients
			quarks=0
			for quark in ggposerver.quarks.values():
				if quark.p1!=None and quark.p2!=None and quark.p1.nick!=None and quark.p2.nick!=None:
					quarks=quarks+1
			out["games"]=quarks

		res = json.dumps(out, indent=4, sort_keys=True);
		self.wfile.write(res)


	#Handler for the GET requests
	def do_GET(self):
		self.send_response(200)
		self.send_header('Content-type','text/html')
		self.end_headers()
		# Send the message
		self.print_dump()
		return

class GGPOError(Exception):
	"""
	Exception thrown by GGPO command handlers to notify client of a server/client error.
	"""
	def __init__(self, code, value):
		self.code = code
		self.value = value

	def __str__(self):
		return repr(self.value)

class GGPOChannel(object):
	"""
	Object representing an GGPO channel.
	"""
	def __init__(self, name, rom, topic, motd='', chunksize=1096):
		self.name = name
		self.rom = rom
		self.topic = topic
		self.motd = motd
		self.chunksize = chunksize
		self.clients = set()

class GGPOQuark(object):
	"""
	Object representing a GGPO quark: an ongoing match that can be spectated.
	"""
	def __init__(self, quark):
		self.quark = quark
		self.p1 = None
		self.p1client = None
		self.p2 = None
		self.p2client = None
		self.spectators = set()
		self.recorded = False
		self.useports = False
		self.channel = None
		self.proxyport = {}

class GGPOClient(SocketServer.BaseRequestHandler):
	"""
	GGPO client connect and command handling. Client connection is handled by
	the `handle` method which sets up a two-way communication with the client.
	It then handles commands sent by the client by dispatching them to the
	handle_ methods.
	"""
	def __init__(self, request, client_address, server):
		self.nick = None		# Client's currently registered nickname
		self.host = client_address	# Client's hostname / ip.
		self.status = 0			# Client's status (0=available, 1=away, 2=playing)
		self.clienttype = None		# can be: player(fba), spectator(fba) or client
		self.previous_status = None	# Client's previous status (0=available, 1=away, 2=playing)
		self.opponent = None		# Client's opponent
		self.quark = None		# Client's quark (in-game uri)
		self.fbaport = 0		# Emulator's fbaport
		self.side = 0			# Client's side: 1=P1, 2=P2 (0=spectator before savestate, 3=spectator after savestate)
		self.port = 6009		# Client's port
		self.city = "null"		# Client's city
		self.country = "null"		# Client's country
		self.cc = "null"		# Client's country code
		self.lastmsg = 0		# timestamp of the last chat message
		self.useports = False		# set to true when we have potential problems with NAT traversal
		self.version = 0		# client version
		self.warnmsg = ''		# Warning message (shown after match)
		self.send_queue = []		# Messages to send to client (strings)
		self.channel = GGPOChannel("lobby",'', "The Lobby")	# Channel the client is in
		self.challenging = {}		# users (GGPOClient instances) that this client is challenging by host

		SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

	def pad2hex(self,l):
		return "".join(reversed(struct.pack('I',l)))

	def sizepad(self,value):
		if value==None:
			return('')
		l=len(value)
		pdu = self.pad2hex(l)
		pdu += value
		return pdu

	def reply(self,sequence,pdu):

		length=4+len(pdu)
		return self.pad2hex(length) + self.pad2hex(sequence) + pdu

	def send_ack(self, sequence):
		ACK='\x00\x00\x00\x00'
		response = self.reply(sequence,ACK)
		logging.debug('ACK to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)

	def get_client_from_nick(self,nick):
		try:
			clients = dict(self.server.clients)
			for client_nick in clients:
				if client_nick == nick:
					return self.server.clients[nick]

			for client_nick in self.channel.clients:
				if client_nick == nick:
					return self.channel.clients[nick]
		except KeyError:
			pass

		# if not found, return self
		logging.info('[%s] WARNING: Could not find client: %s (returning self)' % (self.client_ident(), nick))
		return self

	def check_quark_format(self,quark):
		a = re.compile("^challenge\-[0-9]{4}\-[0-9]{10,11}[.][0-9]{2}$")
		if a.match(quark):
			return True
		else:
			return False

	def geolocate(self, ip):
		iso_code=''
		country=''
		city=''
		try:
			response = reader.city(ip)

			if response.country.iso_code!=None:
				iso_code=str(response.country.iso_code)
			if response.country.name!=None:
				country=str(response.country.name)
			#if response.city.name!=None:
				#city=str(response.city.name)

			if (response.subdivisions.most_specific.name=="Barcelona" or
			    response.subdivisions.most_specific.name=="Tarragona" or
			    response.subdivisions.most_specific.name=="Lleida" or
			    response.subdivisions.most_specific.name=="Girona"):
				iso_code="Catalonia"
				country="Catalonia"
		except:
			pass

		return iso_code,country,city

	def parse(self, data):

		response = ''
		logging.debug('[PARSE] from %s: %r' % (self.client_ident(), data))

		length=int(data[0:4].encode('hex'),16)
		if (len(data)<length-4): return()
		sequence=0

		if (length >= 4):
			sequence=int(data[4:8].encode('hex'),16)

		if (length >= 8):
			command=int(data[8:12].encode('hex'),16)
			if (command==0):
				command = "connect"
				params = sequence
			if (command==1):
				command = "auth"
				nicklen=int(data[12:16].encode('hex'),16)
				nick=data[16:16+nicklen]
				passwordlen=int(data[16+nicklen:16+nicklen+4].encode('hex'),16)
				password=data[20+nicklen:20+nicklen+passwordlen]
				port=int(data[20+nicklen+passwordlen:24+nicklen+passwordlen].encode('hex'),16)
				if len(data) > 24+nicklen+passwordlen:
					version=int(data[24+nicklen+passwordlen:28+nicklen+passwordlen].encode('hex'),16)
				else:
					version=0
				params=nick,password,port,version,sequence

			if (command==2):
				if self.nick==None: return()
				command = "motd"
				params = sequence

			if (command==3):
				if self.nick==None: return()
				command="list"
				params = sequence

			if (command==4):
				if self.nick==None: return()
				command="users"
				params = sequence

			if (command==5):
				if self.nick==None: return()
				command="join"
				channellen=int(data[12:16].encode('hex'),16)
				channel=data[16:16+channellen]
				params = channel,sequence

			if (command==6):
				if self.nick==None: return()
				command="status"
				status=int(data[12:16].encode('hex'),16)
				params = status,sequence

			if (command==7):
				if self.nick==None: return()
				command="privmsg"
				msglen=int(data[12:16].encode('hex'),16)
				msg=data[16:16+msglen]
				params = msg,sequence

			if (command==8):
				if self.nick==None: return()
				command="challenge"
				nicklen=int(data[12:16].encode('hex'),16)
				nick=data[16:16+nicklen]
				channellen=int(data[16+nicklen:16+nicklen+4].encode('hex'),16)
				channel=data[20+nicklen:20+nicklen+channellen]
				params = nick,channel,sequence

			if (command==9):
				if self.nick==None: return()
				command="accept"
				nicklen=int(data[12:16].encode('hex'),16)
				nick=data[16:16+nicklen]
				channellen=int(data[16+nicklen:16+nicklen+4].encode('hex'),16)
				channel=data[20+nicklen:20+nicklen+channellen]
				params = nick,channel,sequence

			if (command==0xa):
				if self.nick==None: return()
				command="decline"
				nicklen=int(data[12:16].encode('hex'),16)
				nick=data[16:16+nicklen]
				params = nick,sequence

			if (command==0xb):
				command="getpeer"
				quarklen=int(data[12:16].encode('hex'),16)
				quark=data[16:16+quarklen]
				fbaport=int(data[16+quarklen:16+quarklen+4].encode('hex'),16)
				params = quark,fbaport,sequence

			if (command==0xc):
				command="getnicks"
				quarklen=int(data[12:16].encode('hex'),16)
				quark=data[16:16+quarklen]
				params = quark,sequence

			if (command==0xf):
				command="fba_privmsg"
				quarklen=int(data[12:16].encode('hex'),16)
				quark=data[16:16+quarklen]
				msglen=int(data[16+quarklen:16+quarklen+4].encode('hex'),16)
				msg=data[20+quarklen:20+quarklen+msglen]
				params = quark,msg,sequence

			if (command==0x10):
				if self.nick==None: return()
				command="watch"
				nicklen=int(data[12:16].encode('hex'),16)
				nick=data[16:16+nicklen]
				params = nick,sequence

			if (command==0x11):
				command="savestate"
				quarklen=int(data[12:16].encode('hex'),16)
				quark=data[16:16+quarklen]
				block1=data[16+quarklen:20+quarklen]
				block2=data[20+quarklen:24+quarklen]
				#buflen=int(data[24+quarklen:24+quarklen+4].encode('hex'),16)
				#gamebuf=data[28+quarklen:28+quarklen+buflen]
				gamebuf=data[24+quarklen:length+4]
				params = quark,block1,block2,gamebuf,sequence

			if (command==0x12):
				command="gamebuffer"
				quarklen=int(data[12:16].encode('hex'),16)
				quark=data[16:16+quarklen]
				#buflen=int(data[16+quarklen:16+quarklen+4].encode('hex'),16)
				#gamebuf=data[20+quarklen:20+quarklen+buflen]
				gamebuf=data[20+quarklen:length+4]
				params = quark,gamebuf,sequence

			if (command==0x13):
				command="ggpotv"
				quarklen=int(data[12:16].encode('hex'),16)
				quark=data[16:16+quarklen]
				gamebuf=data[20+quarklen:length+4]
				params = quark,gamebuf,sequence

			if (command==0x14):
				command="spectator"
				quarklen=int(data[12:16].encode('hex'),16)
				quark=data[16:16+quarklen]
				params = quark,sequence

			if (command==0x1c):
				if self.nick==None: return()
				command="cancel"
				nicklen=int(data[12:16].encode('hex'),16)
				nick=data[16:16+nicklen]
				params = nick,sequence

			if command in ["join", "challenge", "decline", "cancel", "accept", "getnicks", "watch", "spectator"]:
				logging.info('[%s] SEQUENCE: %d COMMAND: %s %s' % (self.client_ident(),sequence,command,params[0]))
			elif command in ["savestate", "list"]:
				logging.debug('[%s] SEQUENCE: %d COMMAND: %s' % (self.client_ident(),sequence,command))
			else:
				logging.info('[%s] SEQUENCE: %d COMMAND: %s' % (self.client_ident(),sequence,command))

			try:
				handler = getattr(self, 'handle_%s' % (command), None)
				if not handler:
					logging.info('[%s] No handler for command: %s. Full line: %r' % (self.client_ident(), command, data))
					if self.nick==None: return()
					command="unknown"
					params = sequence
					handler = getattr(self, 'handle_%s' % (command), None)

				response = handler(params)
			except AttributeError, e:
				raise e
				logging.error('[%s] ERROR (1) %s in command %s' % (self.client_ident(), e, command))
			except GGPOError, e:
				response = '[%s] ERROR (2) %s %s in command %s' % (self.client_ident(), e.code, e.value, command)
				logging.error('%s' % (response))
			except Exception, e:
				response = '[%s] ERROR (3) %s in command %s' % (self.client_ident(), repr(e), command)
				logging.error('%s' % (response))
				raise

		if (len(data) > length+4 ):
			pdu=data[length+4:]
			self.parse(pdu)

		return response

	def handle(self):
		logging.info('[%s] Client connected' % (self.client_ident(), ))

		data=''
		while True:
			try:
				ready_to_read, ready_to_write, in_error = select.select([self.request], [], [], 0.1)
			except:
				break

			# Write any commands to the client
			while self.send_queue:
				msg = self.send_queue.pop(0)
				#logging.debug('[SEND] to %s: %r' % (self.client_ident(), msg))
				try:
					self.request.send(msg)
				except:
					logging.info('[%s] Can\'t send data. Finishing ' % (self.client_ident(), ))
					self.finish()

			# See if the client has any commands for us.
			if len(ready_to_read) == 1 and ready_to_read[0] == self.request:
				try:
					dataread=self.request.recv(16384)
					data+=dataread

					if not dataread:
						break
					#logging.debug('[RECV] from %s: %r' % (self.client_ident(), data))

					while (len(data)-4 > int(data[0:4].encode('hex'),16)):
						length=int(data[0:4].encode('hex'),16)
						response = self.parse(data[0:length+4])
						data=data[length+4:]

					if len(data)-4 == int(data[0:4].encode('hex'),16):
						response = self.parse(data)
						data=''

						if response:
							logging.debug('<<<<<<>>>>>to %s: %r' % (self.client_ident(), response))
							#self.request.send(response)

				except Exception, e:
					logging.info('[%s] Can\'t read data. Finishing. ERROR: %s' % (self.client_ident(), repr(e)))
					self.finish()

		self.request.close()

	def get_peer_from_quark(self, quark):
		"""
		Returns a GGPOClient object representing our FBA peer's ggpofba connection, or self if not found
		"""
		connections = dict(self.server.connections)
		for host in connections:
			try:
				client = self.server.connections[host]
				if client.clienttype=="player" and client.quark==quark and client.host!=self.host:
					return client
			except KeyError:
				pass
		return self

	def get_myclient_from_quark(self, quark):
		"""
		Returns a GGPOClient object representing our own client connection, or self if not found
		"""
		try:
			quarkobject = self.server.quarks[quark]

			if quarkobject.p1client!=None and self.nick!=None:
				if quarkobject.p1client.nick == self.nick:
					return quarkobject.p1client

			if quarkobject.p2client!=None and self.nick!=None:
				if quarkobject.p2client.nick == self.nick:
					return quarkobject.p2client
		except KeyError:
			pass

		clients = dict(self.server.clients)
		for nick in clients:
			client = self.get_client_from_nick(nick)
			if client.clienttype=="client" and client.quark==quark and client.host[0]==self.host[0]:
				return client
		return self


	def handle_fba_privmsg(self, params):
		"""
		Handle sending messages inside the FBA emulator.
		"""
		quark, msg, sequence = params

		# send the ACK to the client
		#self.send_ack(sequence)

		peer=self.get_peer_from_quark(quark)

		negseq=4294967288 #'\xff\xff\xff\xf8'
		pdu=self.sizepad(quark)
		pdu+=self.sizepad(self.nick)
		pdu+=self.sizepad(msg)

		response = self.reply(negseq,pdu)
		logging.debug('to %s: %r' % (peer.client_ident(), response))
		peer.send_queue.append(response)
		logging.debug('to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)

	def handle_gamebuffer(self, params):
		quark, gamebuf, sequence = params

		negseq=4294967284 #'\xff\xff\xff\xf4'
		pdu=gamebuf
		response = self.reply(negseq,pdu)

		connections = dict(self.server.connections)
		for host in connections:
			try:
				client = self.server.connections[host]
				if client.clienttype=="spectator" and client.quark==quark and client.side==0:
					logging.debug('to %s: %r' % (client.client_ident(), response))
					client.send_queue.append(response)
					client.side=3
			except KeyError:
				pass

		# record match for future broadcast
		quarkobject = self.server.quarks[quark]
		if self.check_quark_format(quark) and quarkobject.recorded == False:
			quarkobject.recorded=True

			# match started successfully, reset useports on both clients:
			quarkobject.p1client.useports=False
			quarkobject.p2client.useports=False
			quarkobject.p1client.warnmsg=''
			quarkobject.p2client.warnmsg=''

			# store initial savestate (gamebuffer)
			quarkfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'quarks', 'quark-'+quark+'-gamebuffer.fs')
			if not os.path.exists(quarkfile):
				try:
					os.mkdir(os.path.dirname(quarkfile))
				except:
					pass
				f=open(quarkfile, 'wb')
				f.write(response)
				f.close()

			# store player nicknames
			createdb=False
			dbfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'db', 'ggposrv.sqlite3')
			if not os.path.exists(dbfile):
				createdb=True
				try:
					os.mkdir(os.path.dirname(dbfile))
				except:
					pass

			conn = sqlite3.connect(dbfile)
			cursor = conn.cursor()

			if createdb==True:
				cursor.execute("""CREATE TABLE IF NOT EXISTS quarks (
							id INTEGER PRIMARY KEY,
							quark TEXT,
							player1 TEXT,
							player2 TEXT,
							channel TEXT,
							date TEXT,
							realtime_views INTEGER,
							saved_views INTEGER);""")
				cursor.execute("""CREATE UNIQUE INDEX quarks_quark_idx on quarks (quark);""")
				logging.info("[%s] created empty quark database" % (self.client_ident()))

			date = datetime.datetime.today().strftime("%Y-%m-%d %H:%M:%S")
			sql = "INSERT INTO quarks (quark, player1, player2, channel, date, realtime_views, saved_views) VALUES (?,?,?,?,?,0,0)"
			cursor.execute(sql, [quark, quarkobject.p1.nick, quarkobject.p2.nick, quarkobject.channel.name, date])
			conn.commit()
			conn.close()


	def handle_savestate(self, params):
		quark, block1, block2, gamebuf, sequence = params

		# send ACK to the player
		self.send_ack(sequence)

		negseq=4294967283 #'\xff\xff\xff\xf3'
		pdu=block2+block1+gamebuf
		response = self.reply(negseq,pdu)

		connections = dict(self.server.connections)
		for host in connections:
			try:
				client = self.server.connections[host]
				if client.clienttype=="spectator" and client.quark==quark and client.side==3:
					logging.debug('to %s: %r' % (client.client_ident(), response))
					client.send_queue.append(response)
			except KeyError:
				pass

		# record match for future broadcast
		try:
			quarkobject = self.server.quarks[quark]
		except KeyError:
			return()

		if self.check_quark_format(quark) and quarkobject.recorded == True:
			quarkfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'quarks', 'quark-'+quark+'-savestate.fs')
			if not os.path.exists(quarkfile):
				try:
					os.mkdir(os.path.dirname(quarkfile))
				except:
					pass
			try:
				f=open(quarkfile, 'ab')
				f.write(response)
				f.close()
			except IOError:
				logging.error('[%s] IOError in command savestate' % (self.client_ident()))

	def handle_getnicks(self, params):
		quark, sequence = params

		# to replay a saved quark
		try:
			quarkobject = self.server.quarks[quark]
		except KeyError:

			# make sure the quark format is valid
			if not self.check_quark_format(quark):
				return()

			quarkfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'quarks', 'quark-'+quark+'-gamebuffer.fs')
			if not os.path.exists(quarkfile):
				return()

			dbfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'db', 'ggposrv.sqlite3')
			if not os.path.exists(dbfile):
				return()

			conn = sqlite3.connect(dbfile)
			cursor = conn.cursor()
			sql = "SELECT player1, player2, channel FROM quarks WHERE quark=?"
			cursor.execute(sql, [(quark)])
			player1,player2,channel=cursor.fetchone()
			conn.close()

			if channel=='':
				channel="lobby"

			if channel=='ssf2t':
				channel="ssf2xj"

			pdu='\x00\x00\x00\x00'
			pdu+=self.sizepad(player1)
			pdu+=self.sizepad(player2)
			pdu+='\x00\x00\x00\x00'
			pdu+=self.pad2hex(0)

			response = self.reply(sequence,pdu)
			logging.debug('to %s: %r' % (self.client_ident(), response))
			self.request.send(response)

			# now broadcast the quark to the client

			f=open(quarkfile, 'rb')
			response = f.read()
			f.close()
			logging.debug('to %s: %r' % (self.client_ident(), response))
			self.request.send(response)
			self.side=3

			quarkfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'quarks', 'quark-'+quark+'-savestate.fs')
			if not os.path.exists(quarkfile):
				quarkfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'quarks', 'quark-'+quark+'-savestate.fs.gz')
				if not os.path.exists(quarkfile):
					return()

			if quarkfile.endswith(".gz"):
				f=gzip.open(quarkfile)
			else:
				f=open(quarkfile)

			try:
				CHUNKSIZE=self.server.channels[channel].chunksize
			except:
				CHUNKSIZE=1096
			response = f.read(CHUNKSIZE)
			while (response):
				time.sleep(0.8)
				try:
					logging.debug('to %s: %r' % (self.client_ident(), response))
					self.request.send(response)
				except:
					logging.debug('[%s]: spectator disconnected from broadcast' % (self.client_ident()))
					break

				response = f.read(CHUNKSIZE)
			f.close()
			self.request.close()
			return()

		i=0
		while True:
			if (quarkobject.p1 != None and quarkobject.p2 != None) or i>=30:
				break
			i=i+1
			time.sleep(1)

		pdu='\x00\x00\x00\x00'
		if (i<30):
			pdu+=self.sizepad(quarkobject.p1.nick)
			pdu+=self.sizepad(quarkobject.p2.nick)
		else:
			# avoid crashing fba if we can't get our peer
			pdu+='\x00\x00\x00\x00'
			pdu+='\x00\x00\x00\x00'

		pdu+='\x00\x00\x00\x00'
		if self.clienttype=="player":
			pdu+=self.pad2hex(len(quarkobject.spectators))
		else:
			pdu+=self.pad2hex(len(quarkobject.spectators)+1)

		response = self.reply(sequence,pdu)
		logging.debug('to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)

		if self.clienttype=="player":
			# call auto_spectate() to record the game
			logging.info('[%s] calling AUTO-SPECTATE' % (self.client_ident()))
			self.auto_spectate(quark)

			# announce the match to the public
			myself=self.get_myclient_from_quark(quark)
			myself.previous_status=myself.status
			myself.status=2
			params = 2,0
			myself.handle_status(params)

	def handle_getpeer(self, params):
		quark, fbaport, sequence = params

		# send ack to the client's ggpofba
		self.send_ack(sequence)

		self.clienttype="player"
		self.quark=quark
		self.fbaport=fbaport

		quarkobject = self.server.quarks.setdefault(quark, GGPOQuark(quark))
		myself=self.get_myclient_from_quark(quark)
		self.side=myself.side
		self.nick=myself.nick
		self.useports=myself.useports
		self.channel=myself.channel
		quarkobject.channel=myself.channel

		if quarkobject.p1!=None and quarkobject.p2!=None:
			logging.info('[%s] getpeer in a full quark: go away' % (self.client_ident()))
			self.finish()
			return

		i=0
		while True:
			i=i+1
			time.sleep(0.8)
			peer=self.get_peer_from_quark(quark)
			if peer!=self or i>=30:
				break

		if peer==self:
			logging.info('[%s] couldn\'t find peer: %s' % (self.client_ident() , peer.client_ident()))
		else:
			logging.info('[%s] found peer: %s [my fbaport: %d ; peer fbaport: %d]' % (self.client_ident() , peer.client_ident(), self.fbaport, peer.fbaport))

		selfchallenge=False
		if self.side==1 and quarkobject.p1==None:
			quarkobject.p1=self
			quarkobject.p1client=myself
		elif self.side==2 and quarkobject.p2==None:
			quarkobject.p2=self
			quarkobject.p2client=myself
		else:
			# you are challenging yourself
			if (quarkobject.p1==None):
				quarkobject.p1=self
				quarkobject.p1client=myself
			if (quarkobject.p2==None):
				quarkobject.p2=self
				quarkobject.p2client=myself
			selfchallenge=True

		negseq=4294967289 #'\xff\xff\xff\xf9'
		if holepunch and self.useports==False and peer.useports==False and quarkobject.useports==False:
			# when UDP hole punching is enabled clients must use the udp proxy wrapper
			pdu=self.sizepad("127.0.0.1")
			if selfchallenge:
				pdu+=self.pad2hex(7002)
			else:
				ip = self.host[0]
				try:
					port = int(quarkobject.proxyport[ip])
				except:
					port = 7001
				pdu+=self.pad2hex(port)

			if (int(self.host[1])>6009 or int(self.host[1])<6000) and myself.version < 32:
				myself.useports=True
				logging.info('[%s] using holepunch with %s on quark %s (and setting useports=True)' % (self.client_ident(), peer.client_ident(), quark))

		else:
			if holepunch:
				# if we can't do nat traversal with holepunch, try to use open ports instead
				logging.info('[%s] WARNING: not using holepunch with %s on quark %s' % (self.client_ident(), peer.client_ident(), quark))

				if int(self.host[1])>6009 or int(self.host[1])<6000 and myself!=None:
					msg="Looks like FightCade is having problems doing NAT traversal on your connection.\n"
					msg+="If you can't connect try opening GGPO ports on your router"
					if (myself.version < 37):
						msg+=" and update to the latest version of FightCade."
					else:
						msg+="."
					myself.warnmsg=msg
					# warn the other peer that he's innocent:
					if int(peer.host[1])<=6009 and int(peer.host[1])>=6000 and quarkobject!=None:
						peer_nick = myself.nick
						if peer_nick==None or peer_nick=='':
							peer_nick="your peer"
						msg="Looks like "+str(peer_nick)+" has problems connecting (problem is on his side, not on yours).\n"
						msg+="If you can't connect with him try opening GGPO ports on your router"
						if quarkobject.p1client==myself and quarkobject.p2client!=None:
							if (quarkobject.p2client.version < 37):
								msg+=" and update to the latest version of FightCade."
							else:
								msg+="."
							quarkobject.p2client.warnmsg=msg
						elif quarkobject.p2client==myself and quarkobject.p1client!=None:
							if (quarkobject.p1client.version < 37):
								msg+=" and update to the latest version of FightCade."
							else:
								msg+="."
							quarkobject.p1client.warnmsg=msg

				if int(peer.host[1])>6009 or int(peer.host[1])<6000 and quarkobject!=None:
					msg="Looks like FightCade is having problems doing NAT traversal on your connection.\n"
					msg+="If you can't connect try opening GGPO ports on your router."
					if quarkobject.p1client==myself and quarkobject.p2client!=None:
						quarkobject.p2client.warnmsg=msg
					elif quarkobject.p2client==myself and quarkobject.p1client!=None:
						quarkobject.p1client.warnmsg=msg
					# warn the other peer that he's innocent:
					if int(self.host[1])<=6009 and int(self.host[1])>=6000:
						peer_nick = myself.opponent
						if peer_nick==None or peer_nick=='':
							peer_nick="your peer"
						msg="Looks like "+str(peer_nick)+" has problems connecting (problem is on his side, not on yours).\n"
						msg+="If you can't connect with him try opening GGPO ports on your router."
						myself.warnmsg=msg

			pdu=self.sizepad(peer.host[0])
			pdu+=self.pad2hex(peer.fbaport)
		if self.side==1:
			pdu+=self.pad2hex(1)
		else:
			pdu+=self.pad2hex(0)

		response = self.reply(negseq,pdu)
		logging.debug('to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)

	def auto_spectate(self, quark):

		logging.debug('[%s] entering AUTO-SPECTATE' % (self.client_ident()))

		negseq=4294967285 #'\xff\xff\xff\xf5'
		pdu=''
		response = self.reply(negseq,pdu)

		negseq=4294967286 #'\xff\xff\xff\xf6'
		pdu=self.pad2hex(1)
		response+=self.reply(negseq,pdu)

		# make the player's FBA send us the game data, to store it on the server
		logging.debug('to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)

	def handle_spectator(self,params):
		quark, sequence = params

		try:
			quarkobject = self.server.quarks[quark]
		except KeyError:

			# to replay a saved quark
			logging.info('[%s] spectating saved quark: %s' % (self.client_ident(), quark))

			# send ack to the client's ggpofba
			self.send_ack(sequence)

			self.clienttype="spectator"
			self.quark=quark

			# increment saved views on db
			dbfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'db', 'ggposrv.sqlite3')
			conn = sqlite3.connect(dbfile)
			cursor = conn.cursor()
			sql = "UPDATE quarks SET saved_views=saved_views+1 WHERE quark=?"
			cursor.execute(sql, [quark])
			conn.commit()
			conn.close()

			return()

		logging.info('[%s] spectating real-time quark: %s' % (self.client_ident(), quark))

		# send ack to the client's ggpofba
		self.send_ack(sequence)

		self.clienttype="spectator"
		self.quark=quark

		quarkobject.spectators.add(self)

		negseq=4294967285 #'\xff\xff\xff\xf5'
		pdu=''
		response = self.reply(negseq,pdu)

		negseq=4294967286 #'\xff\xff\xff\xf6'
		pdu=self.pad2hex(len(quarkobject.spectators)+1)
		response+=self.reply(negseq,pdu)

		# this updates the number of spectators in both players FBAs
		logging.debug('to %s: %r' % (quarkobject.p1.client_ident(), response))
		quarkobject.p1.send_queue.append(response)
		logging.debug('to %s: %r' % (quarkobject.p2.client_ident(), response))
		quarkobject.p2.send_queue.append(response)

		for spectator in quarkobject.spectators:
			spectator.send_queue.append(response)

		# increment realtime views on db
		dbfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'db', 'ggposrv.sqlite3')
		conn = sqlite3.connect(dbfile)
		cursor = conn.cursor()
		sql = "UPDATE quarks SET realtime_views=realtime_views+1 WHERE quark=?"
		cursor.execute(sql, [quark])
		conn.commit()
		conn.close()

	def spectator_leave(self, quark):

		quarkobject = self.server.quarks[quark]

		quarkobject.spectators.remove(self)

		negseq=4294967286 #'\xff\xff\xff\xf6'
		pdu=self.pad2hex(len(quarkobject.spectators)+1)
		response=self.reply(negseq,pdu)

		# this updates the number of spectators in both players FBAs
		try:
			logging.debug('to %s: %r' % (quarkobject.p1.client_ident(), response))
			quarkobject.p1.send_queue.append(response)
			logging.debug('to %s: %r' % (quarkobject.p2.client_ident(), response))
			quarkobject.p2.send_queue.append(response)
		except:
			pass

		for spectator in quarkobject.spectators:
			spectator.send_queue.append(response)

	def handle_challenge(self, params):
		nick, channel, sequence = params

		client = self.get_client_from_nick(nick)

		challengespam=False
		timestamp = time.time()
		if (timestamp-self.lastmsg < 0.70):
			challengespam=True

		self.lastmsg = timestamp

		# if we can't find the client, tell the user that this client has parted:
		if client == self and nick!=self.nick:
			negseq=4294967293 #'\xff\xff\xff\xfd'
			pdu=''
			pdu+='\x00\x00\x00\x01' #unk1
			pdu+='\x00\x00\x00\x00' #unk2
			pdu+=self.sizepad(nick)
			response = self.reply(negseq,pdu)
			self.send_queue.append(response)

		# check that user is connected, in available state and in the same channel, and we're not playing
		if (client.status==0 and client.channel==self.channel and self.channel.name==channel and self.status<2 and nick!=self.nick and client!=self and challengespam==False):

			# send ACK to the initiator of the challenge request
			self.send_ack(sequence)

			self.side=1

			# send the challenge request  to the challenged user
			negseq=4294967292 #'\xff\xff\xff\xfc'
			pdu=self.sizepad(self.nick)
			pdu+=self.sizepad(self.channel.name)

			response = self.reply(negseq,pdu)

			logging.debug('to %s: %r' % (client.client_ident(), response))
			client.send_queue.append(response)

			# add the client to the challenging list
			self.challenging[client.host] = client
		else:
			# send the NOACK to the client
			response = self.reply(sequence,'\x00\x00\x00\x0a')
			logging.info('[%s] challenge NO_ACK: tried to challenge client %s (%s) but client.status=%d and self.status=%d and client.channel=%r and self.channel=%r and self.channel.name=%r and channel=%r and spam=%s' % (self.client_ident(), client.client_ident(), nick, client.status, self.status, client.channel, self.channel, self.channel.name, channel, challengespam ))
			self.send_queue.append(response)

	def handle_accept(self, params):
		nick, channel, sequence = params

		# make sure that nick has challenged the user that is doing the accept command
		client = self.get_client_from_nick(nick)

		if self.host not in client.challenging:
			# send the NOACK to the client
			response = self.reply(sequence,'\x00\x00\x00\x0c')
			logging.info('[%s] accept NO_ACK: %r' % (self.client_ident(), response))
			self.send_queue.append(response)
			return
		else:
			#client.challenging.pop(self.host)
			client.challenging.clear()
			self.challenging.clear()

		timestamp = int(time.time())
		random1=random.randint(1000,9999)
		random2=random.randint(10,99)
		quark="challenge-"+str(random1)+"-"+str(timestamp)+"."+str(random2)

		self.quark=quark
		client.quark=quark

		self.side=2
		client.side=1
		self.opponent=nick
		client.opponent=self.nick

		# send the quark stream uri to the user who accepted the challenge
		negseq=4294967290 #'\xff\xff\xff\xfa'
		pdu=''
		pdu+=self.sizepad(self.opponent)
		pdu+=self.sizepad(self.nick)
		pdu+=self.sizepad("quark:served,"+self.channel.name+","+self.quark+",7000")

		response = self.reply(negseq,pdu)
		logging.debug('to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)

		# send the quark stream uri to the challenge initiator
		negseq=4294967290 #'\xff\xff\xff\xfa'
		pdu=''
		pdu+=self.sizepad(client.nick)
		pdu+=self.sizepad(client.opponent)
		pdu+=self.sizepad("quark:served,"+self.channel.name+","+self.quark+",7000")

		response = self.reply(negseq,pdu)
		logging.debug('to %s: %r' % (client.client_ident(), response))
		client.send_queue.append(response)

	def handle_decline(self, params):
		nick, sequence = params

		client = self.get_client_from_nick(nick)

		if self.host not in client.challenging:
			# send the NOACK to the client
			response = self.reply(sequence,'\x00\x00\x00\x0d')
			logging.info('[%s] decline NO_ACK: %r' % (self.client_ident(), response))
			self.send_queue.append(response)
			return
		else:
			client.challenging.pop(self.host)

		# send ACK to the initiator of the decline request
		self.send_ack(sequence)

		# inform of the decline to the initiator of the challenge
		negseq=4294967291 #'\xff\xff\xff\xfb'
		pdu=self.sizepad(self.nick)
		#pdu+=self.sizepad(self.channel.name)

		response = self.reply(negseq,pdu)

		logging.debug('to %s: %r' % (client.client_ident(), response))
		client.send_queue.append(response)

	def handle_watch(self, params):

		nick, sequence = params

		client = self.get_client_from_nick(nick)

		# check that user is connected, in playing state (status=2) and in the same channel
		if (client.status==2 and client.channel==self.channel and client.quark!=None):

			# send ACK to the user who wants to watch the running match
			self.send_ack(sequence)

			# send the quark stream uri to the user who wants to watch
			negseq=4294967290 #'\xff\xff\xff\xfa'
			pdu=''
			pdu+=self.sizepad(client.nick)
			pdu+=self.sizepad(client.opponent)
			pdu+=self.sizepad("quark:stream,"+self.channel.name+","+str(client.quark)+",7000")

			response = self.reply(negseq,pdu)
			logging.debug('to %s: %r' % (self.client_ident(), response))
			self.send_queue.append(response)
		else:
			# send the NOACK to the client
			response = self.reply(sequence,'\x00\x00\x00\x0b')
			logging.info('[%s] watch NO_ACK: %r' % (self.client_ident(), response))
			self.send_queue.append(response)

	def handle_cancel(self, params):
		nick, sequence = params

		client = self.get_client_from_nick(nick)

		if client.host not in self.challenging:
			# send the NOACK to the client
			response = self.reply(sequence,'\x00\x00\x00\x0e')
			logging.info('[%s] cancel NO_ACK: %r' % (self.client_ident(), response))
			self.send_queue.append(response)
			return
		else:
			self.challenging.pop(client.host)

		# send ACK to the challenger user who wants to cancel the challenge
		self.send_ack(sequence)

		# send the cancel action to the challenged user
		negseq=4294967279 #'\xff\xff\xff\xef'
		pdu=self.sizepad(self.nick)

		response = self.reply(negseq,pdu)

		client = self.get_client_from_nick(nick)
		logging.debug('to %s: %r' % (client.client_ident(), response))
		client.send_queue.append(response)

	def handle_ggpotv(self, params):
		# XXX: not sure what to do with this...
		quark, gamebuf, sequence = params
		self.send_ack(sequence)

	def handle_unknown(self, params):
		sequence = params
		response = self.reply(sequence,'\x00\x00\x00\x08')
		logging.debug('to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)
		# kick the user out of the server
		self.finish()

	def handle_connect(self, params):
		sequence = params
		self.send_ack(sequence)
		self.server.connections[self.host] = self

	def handle_motd(self, params):
		sequence = params

		pdu='\x00\x00\x00\x00'

		channel = self.channel

		pdu+=self.sizepad(channel.name)
		pdu+=self.sizepad(channel.topic)
		if self.version >= MIN_CLIENT_VERSION:
			pdu+=self.sizepad(channel.motd+self.dynamic_motd(channel.name))
		else:
			motd='<center>'
			if self.version != 0:
				motd+='You are using FightCade client version {0:.2f}'.format(self.version/100.0)+'\n'
			motd+="*********************************************************\n"
			motd+=" ERROR: YOUR VERSION OF FIGHTCADE CLIENT IS TOO OLD\n"
			motd+=" ERROR: YOUR VERSION OF FIGHTCADE CLIENT IS TOO OLD\n"
			motd+=" ERROR: YOUR VERSION OF FIGHTCADE CLIENT IS TOO OLD\n"
			motd+="*********************************************************\n\n"
			motd+="MINIMUM VERSION REQUIRED TO CONNECT IS: {0:.2f}".format(MIN_CLIENT_VERSION/100.0)+"\n\n"
			motd+="PLEASE RE-DOWNLOAD LATEST VERSION OF FIGHTCADE NOW:\n"
			motd+="\nhttp://www.fightcade.com\n\n"
			motd+="*********************************************************"
			motd+="</center>"
			pdu+=self.sizepad(motd)

		response = self.reply(sequence,pdu)
		logging.debug('to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)

	def kick_client(self, sequence):
		# auth unsuccessful
		response = self.reply(sequence,'\x00\x00\x00\x06')
		logging.debug('to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)
		#self.finish()

	def handle_auth(self, params):
		"""
		Handle the initial setting of the user's nickname
		"""
		nick,password,port,version,sequence = params

		# New connection
		createdb=False
		dbfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'db', 'ggposrv.sqlite3')
		if not os.path.exists(dbfile):
			createdb=True
			try:
				os.mkdir(os.path.dirname(dbfile))
			except:
				pass

		conn = sqlite3.connect(dbfile)
		cursor = conn.cursor()

		if createdb==True:
			cursor.execute("""CREATE TABLE IF NOT EXISTS users (
						id INTEGER PRIMARY KEY,
						username TEXT COLLATE NOCASE,
						password TEXT,
						salt TEXT,
						email TEXT,
						ip TEXT,
						date TEXT);""")
			cursor.execute("""CREATE UNIQUE INDEX users_username_idx on users (username COLLATE NOCASE);""")
			# db is empty, kick the user
			logging.info("[%s] created empty user database" % (self.client_ident()))
			self.kick_client(sequence)
			conn.commit()
			conn.close()
			return

		# fetch the user's salt
		sql = "SELECT salt FROM users WHERE username=?"
		cursor.execute(sql, [(nick)])
		salt=cursor.fetchone()
		if (salt==None):
			# user doesn't exist into database
			logging.info("[%s] user doesn't exist into database: %s" % (self.client_ident(), nick))
			self.kick_client(sequence)
			conn.close()
			return

		# compute the hashed password
		h_password = hmac.new("GGPO-NG", password+salt[0], hashlib.sha512).hexdigest()

		sql = "SELECT COUNT(username) FROM users WHERE password=? AND username=?"
		cursor.execute(sql, [(h_password),(nick)])
		result = cursor.fetchone()
		conn.close()
		if (result[0] != 1):
			# wrong password
			logging.info("[%s] wrong password: %s" % (self.client_ident(), nick))
			self.kick_client(sequence)
			return

		if nick in self.server.clients:
			# Someone else is using the nick
			clone = self.get_client_from_nick(nick)
			if clone != self:
				logging.info("[%s] someone else is using the nick: %s (%s)" % (self.client_ident(), nick, clone.client_ident()))
				#self.server.clients.pop(nick)
				# remove the clone from channel
				clone.handle_part(clone.channel.name)
				clone.request.close()
				#self.kick_client(sequence)
				#self.server.clients.pop(nick)
				#self.request.close()
				#return()

		logging.info("[%s] LOGIN OK. VERSION: %s NICK: %s" % (self.client_ident(), str(version), nick))
		self.nick = nick
		self.server.clients[nick] = self
		self.port = port
		self.clienttype="client"
		self.cc, self.country, self.city = self.geolocate(self.host[0])
		self.version = version

		# auth successful
		self.send_ack(sequence)
		if self.host in self.server.connections:
			self.server.connections.pop(self.host)


	def handle_status(self, params):

		status,sequence = params

		# send ack to the client
		if (sequence >4):
			self.send_ack(sequence)

		if self.status == 2 and sequence!=0 and (status>=0 and status<2) and self.opponent!=None:
			# set previous_status when status is modified while playing
			self.previous_status = status
			return
		elif (status>=0 and status<2) or (status==2 and sequence==0):
			self.status = status
		else:
			# do nothing if the user tries to set an invalid status
			logging.info('[%s]: trying to set invalid status: %d , self.status=%d, sequence=%d, self.opponent=%s' % (self.client_ident(), status, self.status, sequence, self.opponent))
			return

		if self.clienttype=="client":

			negseq=4294967293 #'\xff\xff\xff\xfd'
			pdu2=''
			pdu='\x00\x00\x00\x01'
			pdu+='\x00\x00\x00\x01'
			pdu+=self.sizepad(self.nick)
			pdu+=self.pad2hex(self.status)
			if (self.opponent!=None):
				pdu+=self.sizepad(self.opponent)
			else:
				pdu+='\x00\x00\x00\x00'
			pdu+=self.sizepad(str(self.host[0]))
			pdu+='\x00\x00\x00\x00' #unk1
			pdu+='\x00\x00\x00\x00' #unk2
			pdu+=self.sizepad(self.city)
			pdu+=self.sizepad(self.cc)
			pdu+=self.sizepad(self.country)
			pdu+=self.pad2hex(self.port)
			if (self.opponent!=None):
				client = self.get_client_from_nick(self.opponent)
				pdu2+='\x00\x00\x00\x01'
				pdu2+=self.sizepad(client.nick)
				pdu2+=self.pad2hex(client.status)
				pdu2+=self.sizepad(client.opponent)
				pdu2+=self.sizepad(str(client.host[0]))
				pdu2+='\x00\x00\x00\x00' #unk1
				pdu2+='\x00\x00\x00\x00' #unk2
				pdu2+=self.sizepad(client.city)
				pdu2+=self.sizepad(client.cc)
				pdu2+=self.sizepad(client.country)
				pdu2+=self.pad2hex(client.port)

			# fix for crappy routers that change their own public ip address to something else
			pdu1='\x00\x00\x00\x01'
			pdu1+='\x00\x00\x00\x01'
			pdu1+=self.sizepad(self.nick)
			pdu1+=self.pad2hex(self.status)
			if (self.opponent!=None):
				pdu1+=self.sizepad(self.opponent)
			else:
				pdu1+='\x00\x00\x00\x00'
			pdu1+=self.sizepad("127.0.0.1")
			pdu1+='\x00\x00\x00\x00' #unk1
			pdu1+='\x00\x00\x00\x00' #unk2
			pdu1+=self.sizepad(self.city)
			pdu1+=self.sizepad(self.cc)
			pdu1+=self.sizepad(self.country)
			pdu1+=self.pad2hex(self.port)

			self_response = self.reply(negseq,pdu1+pdu2)
			self.send_queue.append(self_response)

			response = self.reply(negseq,pdu+pdu2)
			clients = self.channel.clients.copy()
			for client in clients:
				# Send message to all client in the channel
				if client != self:
					logging.debug('to %s: %r' % (client.client_ident(), response))
					client.send_queue.append(response)


	def handle_users(self, params):

		sequence = params
		pdu=''
		i=0

		# disconnect the client if it's using an older version
		if (self.version < MIN_CLIENT_VERSION):
			self.finish()
			return()

		clients = self.channel.clients.copy()
		for client in clients:
			i=i+1

			pdu+=self.sizepad(client.nick)
			pdu+=self.pad2hex(client.status) #status
			if (client.opponent!=None):
				pdu+=self.sizepad(client.opponent)
			else:
				pdu+='\x00\x00\x00\x00'
			if client==self:
				pdu+=self.sizepad("127.0.0.1")
			else:
				pdu+=self.sizepad(str(client.host[0]))
			pdu+='\x00\x00\x00\x00' #unk1
			pdu+='\x00\x00\x00\x00' #unk2
			pdu+=self.sizepad(client.city)
			pdu+=self.sizepad(client.cc)
			pdu+=self.sizepad(client.country)
			pdu+=self.pad2hex(client.port)      # port

		response = self.reply(sequence,'\x00\x00\x00\x00'+self.pad2hex(i)+pdu)
		logging.debug('to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)

	def handle_list(self, params):

		sequence = params

		pdu=''
		i=0
		for target in sorted(self.server.channels):
			i=i+1
			channel = self.server.channels.get(target)
			if (self.version < 32):
				pdu+=self.sizepad(channel.name)
				pdu+=self.sizepad(channel.rom)
				topic=str(channel.topic)+" ["+str(len(channel.clients))+"]"
				pdu+=self.sizepad(topic)
				pdu+=self.pad2hex(i)
			else:
				pdu+=self.sizepad(channel.name)
				pdu+=self.sizepad(channel.rom)
				pdu+=self.sizepad(channel.topic)
				pdu+=self.pad2hex(len(channel.clients))
				pdu+=self.pad2hex(i)
		
		response = self.reply(sequence,'\x00\x00\x00\x00'+self.pad2hex(i)+pdu)
		logging.debug('to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)

	def handle_join(self, params):
		"""
		Handle the JOINing of a user to a channel.
		"""

		channel_name,sequence = params

		if not channel_name in self.server.channels or self.nick==None:
			# send the NOACK to the client
			response = self.reply(sequence,'\x00\x00\x00\x08')
			logging.info('[%s] JOIN NO_ACK: %r' % (self.client_ident(), response))
			self.send_queue.append(response)
			return()

		# part from previously joined channel
		self.handle_part(self.channel.name)

		# Add user to the channel (create new channel if not exists)
		channel = self.server.channels.setdefault(channel_name, GGPOChannel(channel_name, channel_name, channel_name))
		channel.clients.add(self)

		# Add channel to user's channel list
		self.channel = channel

		# send the ACK to the client
		self.send_ack(sequence)

		negseq=4294967295 #'\xff\xff\xff\xff'
		response = self.reply(negseq,'')
		logging.debug('CONNECITON ESTABLISHED to %s: %r' % (self.client_ident(), response))
		self.send_queue.append(response)

		params = self.status,0
		self.handle_status(params)

	def handle_privmsg(self, params):
		"""
		Handle sending a message to a channel.
		"""
		msg, sequence = params

		channel = self.channel

		# send the ACK to the client
		self.send_ack(sequence)

		# allow "System" user to send broadcast messages to *ALL* connected users
		negseq=4294967294 #'\xff\xff\xff\xfe'
		response = self.reply(negseq,self.sizepad(self.nick)+self.sizepad(msg))
		if (self.nick=="System"):
			for client in self.server.clients.values():
				if client.clienttype=="client":
					logging.debug('to %s: %r' % (client.client_ident(), response))
					client.send_queue.append(response)
			return

		timestamp = time.time()
		if (timestamp-self.lastmsg < 0.70):
			nick="System"
			msg="Please do not spam"
			negseq=4294967294 #'\xff\xff\xff\xfe'
			response = self.reply(negseq,self.sizepad(nick)+self.sizepad(msg))
			logging.debug('to %s: %r' % (self.client_ident(), response))
			self.send_queue.append(response)
			self.lastmsg = timestamp
			return

		self.lastmsg = timestamp

		negseq=4294967294 #'\xff\xff\xff\xfe'
		response = self.reply(negseq,self.sizepad(self.nick)+self.sizepad(msg))
		self.send_queue.append(response)
		clients = self.channel.clients.copy()
		for client in clients:
			# Send message to all client in the channel
			if client != self:
				logging.debug('to %s: %r' % (client.client_ident(), response))
				client.send_queue.append(response)

	def handle_part(self, params):
		"""
		Handle a client parting from channel(s).
		"""
		pchannel = params
		# Send message to all clients in the channel user is in, and
		# remove the user from the channel.
		channel = self.server.channels.get(pchannel)

		negseq=4294967293 #'\xff\xff\xff\xfd'
		pdu=''
		pdu+='\x00\x00\x00\x01' #unk1
		pdu+='\x00\x00\x00\x00' #unk2
		pdu+=self.sizepad(self.nick)

		response = self.reply(negseq,pdu)

		clients = self.channel.clients.copy()
		for client in clients:
			if client != self:
				# Send message to all client in the channel except ourselves
				logging.debug('to %s: %r' % (client.client_ident(), response))
				client.send_queue.append(response)

		if self in channel.clients:
			channel.clients.remove(self)

	def dynamic_motd(self, channel):
		motd=''

		# generic motd
		motdfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'motd', 'motd.txt')
		if os.path.exists(motdfile):
			f=open(motdfile, 'r')
			for line in f.readlines():
				motd+=line
			f.close()
			motd+='\n'

		# channel specific motd
		motdfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'motd', channel+'.txt')
		if os.path.exists(motdfile):
			f=open(motdfile, 'r')
			for line in f.readlines():
				motd+=line
			f.close()
			motd+='\n'

		# dynamic motd
		motd+='-!- FightCade server version {0:.2f}'.format(VERSION/100.0)+'\n'
		if self.version > 0:
			motd+='-!- You are using FightCade client version {0:.2f}'.format(self.version/100.0)+'\n'

		clients = len(self.server.clients)
		if clients==1:
			motd+='-!- You are the first client on the server!\n'
		else:
			motd+='-!- There are '+str(clients)+' clients connected to the server.\n'

		#quarks = len(self.server.quarks)
		quarks=0
		for quark in self.server.quarks.values():
			if quark.p1!=None and quark.p2!=None and quark.p1.nick!=None and quark.p2.nick!=None:
				quarks=quarks+1

		if quarks==0:
			motd+='-!- At the moment no one is playing :(\n'
		elif quarks==1:
			motd+='-!- There is only one ongoing game.\n'
		elif quarks>1:
			motd+='-!- There are '+str(quarks)+' ongoing games.\n'

		return motd

	def handle_dump(self):
		"""
		Dump internal server information for debugging purposes.
		"""
		print "Clients:"
		for client in self.server.clients.values():
			print " ", client
			print "     ", client.channel.name
		print "Channels:"
		for channel in self.server.channels.values():
			print " ", channel.name, channel
			for client in channel.clients:
				print "     ", client.nick, client

	def client_ident(self):
		"""
		Return the client identifier as included in many command replies.
		"""
		return('%s@%s:%s#%s/%s(%s)' % (self.nick, self.host[0], self.host[1], self.channel.name, self.clienttype, self.quark))

	def finish(self):
		"""
		The client conection is finished. Do some cleanup to ensure that the
		client doesn't linger around in any channel or the client list.
		"""
		logging.info('[%s] Client disconnected' % (self.client_ident()))
		if self in self.channel.clients:
			# Client is gone without properly QUITing or PARTing this
			# channel.
			clients = self.channel.clients.copy()
			for client in clients:
				# if the gone client was playing against someone, update his status
				if (client.opponent==self.nick):
					client.opponent=None
			#self.channel.clients.remove(self)
			self.handle_part(self.channel.name)
			logging.info("[%s] removing myself from channel" % (self.client_ident()))

		if self.nick in self.server.clients and self.clienttype=="client":
			self.server.clients.pop(self.nick)
			logging.info("[%s] removing myself from server clients" % (self.client_ident()))

		if self.clienttype=="player":

			# return the client to non-playing state when the emulator closes
			myself=self.get_myclient_from_quark(self.quark)
			logging.info("[%s] cleaning: %s" % (self.client_ident(), myself.client_ident()))

			myself.side=0
			myself.opponent=None
			myself.quark=None
			if (myself.previous_status!=None and myself.previous_status!=2):
				myself.status=myself.previous_status
			else:
				myself.status=0
			myself.previous_status=None
			params = myself.status,0
			myself.handle_status(params)

			try:
				quarkobject = self.server.quarks[self.quark]

				# try to clean our peer's client too
				if quarkobject.p1==self and quarkobject.p2!=None:
					mypeer = self.get_client_from_nick(quarkobject.p2.nick)
				elif quarkobject.p2==self and quarkobject.p1!=None:
					mypeer = self.get_client_from_nick(quarkobject.p1.nick)
				else:
					mypeer = self

				mypeer.side=0
				mypeer.opponent=None
				if (mypeer != self):
					mypeer.quark=None
				if (mypeer.previous_status!=None and mypeer.previous_status!=2):
					mypeer.status=mypeer.previous_status
				else:
					mypeer.status=0
				mypeer.previous_status=None
				params = mypeer.status,0
				mypeer.handle_status(params)

				# if connection didn't succeed, send the warning message to both peers
				nick="System"
				negseq=4294967294 #'\xff\xff\xff\xfe'
				if myself.warnmsg!='' and myself.clienttype=="client" and myself.host[0]!=mypeer.host[0]:
					response = self.reply(negseq,self.sizepad(str(nick))+self.sizepad(str(myself.warnmsg)))
					myself.send_queue.append(response)
					logging.info("[%s] sending warnmsg to %s : %s" % (self.client_ident(), myself.client_ident(), myself.warnmsg.replace('\n', ' ') ))
				myself.warnmsg=''

				if mypeer.warnmsg!='' and mypeer.clienttype=="client" and myself.host[0]!=mypeer.host[0]:
					response = self.reply(negseq,self.sizepad(str(nick))+self.sizepad(str(mypeer.warnmsg)))
					mypeer.send_queue.append(response)
					logging.info("[%s] sending warnmsg to %s : %s" % (self.client_ident(), mypeer.client_ident(), mypeer.warnmsg.replace('\n', ' ') ))
				mypeer.warnmsg=''

				# remove quark if we are a player that closes ggpofba
				if quarkobject.p1==self or quarkobject.p2==self and self.quark!=None:
					# this will kill the emulators to avoid assertion failed errors with future players
					# produces an ugly "guru meditation" error on the peer's FBA, but lets the player
					# do another game without having to cross challenge
					# --- comenting it for now, as it freezes the windows client :/
					#logging.info("[%s] killing both FBAs" % (self.client_ident()))
					#quarkobject.p1.send_queue.append('\xff\xff\x00\x00\xde\xad')
					#quarkobject.p2.send_queue.append('\xff\xff\x00\x00\xde\xad')
					logging.info("[%s] removing quark: %s" % (self.client_ident(), self.quark))
					self.server.quarks.pop(self.quark)

					# compress replay data
					quarkfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'quarks', 'quark-'+str(quarkobject.quark)+'-savestate.fs')
					gz_quarkfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'quarks', 'quark-'+str(quarkobject.quark)+'-savestate.fs.gz')
					if not os.path.exists(gz_quarkfile) and os.path.exists(quarkfile):
						logging.info("[%s] compressing replay data for quark %s" % (self.client_ident(), self.quark))
						f_out = gzip.open(gz_quarkfile, 'wb')
						f_in = open(quarkfile, 'rb')
						f_out.writelines(f_in)
						f_out.close()
						f_in.close()
						try:
							os.unlink(quarkfile)
						except:
							pass

					# broadcast the quark id for replays
					quarkfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'quarks', 'quark-'+str(quarkobject.quark)+'-gamebuffer.fs')
					if os.path.exists(quarkfile):
						nick="System"
						msg = "To replay your match, type /replay "+str(quarkobject.quark)+"@"+str(quarkobject.channel.name)
						negseq=4294967294 #'\xff\xff\xff\xfe'
						response = self.reply(negseq,self.sizepad(str(nick))+self.sizepad(str(msg)))
						logging.debug('to %s: %r' % (self.client_ident(), response))
						if (quarkobject.p1client!=None):
							quarkobject.p1client.send_queue.append(response)
						if (quarkobject.p2client!=None):
							quarkobject.p2client.send_queue.append(response)

				if quarkobject.p1==self and self.quark!=None and quarkobject.p2!=None:
					logging.info("[%s] killing peer connection: %s" % (self.client_ident(), quarkobject.p2.client_ident()))
					quarkobject.p2.request.close()
				if quarkobject.p2==self and self.quark!=None and quarkobject.p1!=None:
					logging.info("[%s] killing peer connection: %s" % (self.client_ident(), quarkobject.p1.client_ident()))
					quarkobject.p1.request.close()

			except KeyError, AttributeError:
				pass

		if self.clienttype=="spectator":
			# this client is an spectator
			try:
				logging.info("[%s] spectator leaving quark %s" % (self.client_ident(), self.quark))
				self.spectator_leave(self.quark)
			except KeyError, AttributeError:
				pass

		if self.host in self.server.connections:
			self.server.connections.pop(self.host)
			logging.info("[%s] removing myself from server connections" % (self.client_ident()))

		logging.info('[%s] Connection finished' % (self.client_ident()))
		self.request.close()

	def __repr__(self):
		"""
		Return a user-readable description of the client
		"""
		return('<%s %s@%s>' % (
			self.__class__.__name__,
			self.nick,
			self.host[0],
			)
		)

class GGPOServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
	daemon_threads = True
	allow_reuse_address = True

	def __init__(self, server_address, RequestHandlerClass):
		self.servername = 'localhost'
		self.channels = {} # Existing channels (GGPOChannel instances) by channelname
		self.channels['1941']=GGPOChannel("1941", "1941", '1941 - Counter Attack (World)')
		self.channels['1944']=GGPOChannel("1944", "1944", '1944 - the loop master (000620 USA)')
		self.channels['19xx']=GGPOChannel("19xx", "19xx", '19XX - the war against destiny (951207 USA)', '', 376)
		self.channels['2020bb']=GGPOChannel("2020bb", "2020bb", '2020 Super Baseball (set 1)', '', 1096)
		self.channels['3countb']=GGPOChannel("3countb", "3countb", '3 Count Bout')
		self.channels['agallet']=GGPOChannel("agallet", "agallet", 'Air Gallet')
		self.channels['alpham2']=GGPOChannel("alpham2", "alpham2", 'Alpha Mission II')
		self.channels['androdun']=GGPOChannel("androdun", "androdun", 'Andro Dunos')
		self.channels['aodk']=GGPOChannel("aodk", "aodk", 'Aggressors of Dark Kombat')
		self.channels['aof2']=GGPOChannel("aof2", "aof2", 'Art of Fighting 2 (set 1)')
		self.channels['aof3']=GGPOChannel("aof3", "aof3", 'Art of Fighting 3 - the path of the warrior', '', 1096)
		self.channels['aof']=GGPOChannel("aof", "aof", 'Art of Fighting')
		self.channels['armwar']=GGPOChannel("armwar", "armwar", 'Armored Warriors (941024 Europe)')
		self.channels['avsp']=GGPOChannel("avsp", "avsp", 'Alien vs Predator (940520 Euro)', '', 376)
		self.channels['bangbead']=GGPOChannel("bangbead", "bangbead", 'Bang Bead', '', 1096)
		self.channels['batcir']=GGPOChannel("batcir", "batcir", 'Battle Circuit (970319 Euro)')
		self.channels['bjourney']=GGPOChannel("bjourney", "bjourney", "Blue's Journey")
		self.channels['blazstar']=GGPOChannel("blazstar", "blazstar", 'Blazing Star')
		self.channels['breakers']=GGPOChannel("breakers", "breakers", 'Breakers')
		self.channels['breakrev']=GGPOChannel("breakrev", "breakrev", 'Breakers Revenge', '', 1096)
		self.channels['burningf']=GGPOChannel("burningf", "burningf", 'Burning Fight (set 1)')
		self.channels['captcomm']=GGPOChannel("captcomm", "captcomm", 'Captain Commando (911014 other country)', '', 736)
		self.channels['cawing']=GGPOChannel("cawing", "cawing", 'Carrier Air Wing (U.S. navy 901012 etc)')
		self.channels['crsword']=GGPOChannel("crsword", "crsword", 'Crossed Swords')
		self.channels['csclub']=GGPOChannel("csclub", "csclub", 'Capcom Sports Club (970722 Euro)', '', 376)
		self.channels['cyberlip']=GGPOChannel("cyberlip", "cyberlip", 'Cyber-Lip')
		self.channels['cybots']=GGPOChannel("cybots", "cybots", 'Cyberbots - fullmetal madness (950424 Euro)', '', 376)
		self.channels['ddonpach']=GGPOChannel("ddonpach", "ddonpach", 'DoDonPachi (1997 2/5 master ver, international)', '', 376)
		self.channels['ddsom']=GGPOChannel("ddsom", "ddsom", 'Dungeons & Dragons - shadow over mystara (960619 Euro)', '', 376)
		self.channels['ddtod']=GGPOChannel("ddtod", "ddtod", 'Dungeons & Dragons - tower of doom (940412 Euro)')
		self.channels['dimahoo']=GGPOChannel("dimahoo", "dimahoo", 'Dimahoo (000121 Euro)')
		self.channels['dino']=GGPOChannel("dino", "dino", 'Cadillacs & Dinosaurs (930201 etc)', '', 496)
		self.channels['donpachi']=GGPOChannel("donpachi", "donpachi", 'DonPachi (ver. 1.01 1995/05/11, U.S.A)')
		self.channels['doubledr']=GGPOChannel("doubledr", "doubledr", 'Double Dragon', '', 1096)
		self.channels['ecofghtr']=GGPOChannel("ecofghtr", "ecofghtr", 'Eco Fighters (931203 etc)')
		self.channels['eightman']=GGPOChannel("eightman", "eightman", 'Eight Man')
		self.channels['esprade']=GGPOChannel("esprade", "esprade", 'ESP Ra.De. (1998 4/22 international ver.)', '', 376)
		self.channels['fatfursp']=GGPOChannel("fatfursp", "fatfursp", 'Fatal Fury Special (set 1)', '', 1096)
		self.channels['fatfury1']=GGPOChannel("fatfury1", "fatfury1", 'Fatal Fury - king of fighters')
		self.channels['fatfury2']=GGPOChannel("fatfury2", "fatfury2", 'Fatal Fury 2')
		self.channels['fatfury3']=GGPOChannel("fatfury3", "fatfury3", 'Fatal Fury 3 - road to the final victory')
		self.channels['fbfrenzy']=GGPOChannel("fbfrenzy", "fbfrenzy", 'Football Frenzy')
		self.channels['feversos']=GGPOChannel("feversos", "feversos", 'Fever SOS (International ver. Fri Sep 25 1998)')
		self.channels['ffight']=GGPOChannel("ffight", "ffight", 'Final Fight (World)', '', 736)
		self.channels['fightfev']=GGPOChannel("fightfev", "fightfev", 'Fight Fever (set 1)')
		self.channels['flipshot']=GGPOChannel("flipshot", "flipshot", 'Battle Flip Shot')
		self.channels['forgottn']=GGPOChannel("forgottn", "forgottn", 'Forgotten Worlds (US)')
		self.channels['gaia']=GGPOChannel("gaia", "gaia", 'Gaia Crusaders')
		self.channels['galaxyfg']=GGPOChannel("galaxyfg", "galaxyfg", 'Galaxy Fight - universal warriors')
		self.channels['ganryu']=GGPOChannel("ganryu", "ganryu", 'Ganryu')
		self.channels['garou']=GGPOChannel("garou", "garou", 'Garou - mark of the wolves (set 1)', '', 1096)
		self.channels['garouo']=GGPOChannel("garouo", "garouo", 'Garou - mark of the wolves (set 2)')
		self.channels['ghostlop']=GGPOChannel("ghostlop", "ghostlop", 'Ghostlop [Prototype]')
		self.channels['ghouls']=GGPOChannel("ghouls", "ghouls", "Ghouls'n Ghosts (World)", '', 736)
		self.channels['gigawing']=GGPOChannel("gigawing", "gigawing", 'Giga Wing (990222 USA)')
		self.channels['goalx3']=GGPOChannel("goalx3", "goalx3", 'Goal! Goal! Goal!')
		self.channels['gowcaizr']=GGPOChannel("gowcaizr", "gowcaizr", 'Voltage Fighter - Gowcaizer')
		self.channels['guwange']=GGPOChannel("guwange", "guwange", 'Guwange (Japan, 1999 6/24 master ver.)')
		self.channels['hsf2']=GGPOChannel("hsf2", "hsf2", 'Hyper Street Fighter 2: The Anniversary Edition (040202 Asia)', '', 376)
		self.channels['jojobane']=GGPOChannel("jojobane", "jojobane", "JoJo's Bizarre Adventure", '', 496)
		self.channels['jojon']=GGPOChannel("jojon", "jojon", "JoJo's Venture")
		self.channels['kabukikl']=GGPOChannel("kabukikl", "kabukikl", 'Kabuki Klash - far east of eden', '', 1096)
		self.channels['karnovr']=GGPOChannel("karnovr", "karnovr", "Karnov's Revenge", '', 1096)
		self.channels['kf2k5uni']=GGPOChannel("kf2k5uni", "kf2k5uni", 'King of Fighters 10th Anniversary 2005 Unique (bootleg of kof2002)', '', 1096)
		self.channels['kizuna']=GGPOChannel("kizuna", "kizuna", 'Kizuna Encounter - super tag battle', '', 1096)
		self.channels['knights']=GGPOChannel("knights", "knights", 'Knights of the Round (911127 etc)')
		self.channels['kod']=GGPOChannel("kod", "kod", 'King of Dragons (910711 etc)')
		self.channels['kof2000']=GGPOChannel("kof2000", "kof2000", 'King of Fighters 2000', '', 1096)
		self.channels['kof2001']=GGPOChannel("kof2001", "kof2001", 'King of Fighters 2001 (set 1)', '', 1096)
		self.channels['kof2002']=GGPOChannel("kof2002", "kof2002", 'King of Fighters 2002 - challenge to ultimate battle', '', 1096)
		self.channels['kof2003']=GGPOChannel("kof2003", "kof2003", 'King of Fighters 2003 (MVS)', '', 1096)
		self.channels['kof2k4se']=GGPOChannel("kof2k4se", "kof2k4se", 'King of Fighters Special Edition 2004 (bootleg of kof2002)', '', 1096)
		self.channels['kof94']=GGPOChannel("kof94", "kof94", "King of Fighters '94", '', 1096)
		self.channels['kof95']=GGPOChannel("kof95", "kof95", "King of Fighters '95 (set 1)", '', 1096)
		self.channels['kof96']=GGPOChannel("kof96", "kof96", "King of Fighters '96 (set 1)", '', 1096)
		self.channels['kof97']=GGPOChannel("kof97", "kof97", "King of Fighters '97 (set 1)", '', 1096)
		#self.channels['kof98-2']=GGPOChannel("kof98-2", "kof98", "King of Fighters '98 (Room 2)")
		#self.channels['kof98-3']=GGPOChannel("kof98-3", "kof98", "King of Fighters '98 (Room 3)")
		#self.channels['kof98']=GGPOChannel("kof98", "kof98", "King of Fighters '98 (Room 1)")
		self.channels['kof98']=GGPOChannel("kof98", "kof98", "King of Fighters '98", '', 1096)
		self.channels['kof99']=GGPOChannel("kof99", "kof99", "King of Fighters '99 - millennium battle (set 1)", '', 1096)
		self.channels['kotm2']=GGPOChannel("kotm2", "kotm2", 'King of the Monsters 2 - the next thing')
		self.channels['kotm']=GGPOChannel("kotm", "kotm", 'King of the Monsters (set 1)')
		self.channels['kov']=GGPOChannel("kov", "kov", 'Knights of Valour')
		self.channels['lastblad']=GGPOChannel("lastblad", "lastblad", 'Last Blade (set 1)')
		self.channels['lastbld2']=GGPOChannel("lastbld2", "lastbld2", 'Last Blade 2', '', 1096)
		self.channels['lbowling']=GGPOChannel("lbowling", "lbowling", 'League Bowling', '', 1096)
		self.channels['lobby']=GGPOChannel("lobby", '', "The Lobby", '', 1096)
		self.channels['lresort']=GGPOChannel("lresort", "lresort", 'Last Resort')
		self.channels['magdrop2']=GGPOChannel("magdrop2", "magdrop2", 'Magical Drop II')
		self.channels['magdrop3']=GGPOChannel("magdrop3", "magdrop3", 'Magical Drop III', '', 1096)
		self.channels['matrim']=GGPOChannel("matrim", "matrim", 'Power Instinct Matrimelee', '', 1096)
		self.channels['megaman2']=GGPOChannel("megaman2", "megaman2", 'Mega Man 2 - the power fighters (960708 USA)', '', 376)
		self.channels['mercs']=GGPOChannel("mercs", "mercs", 'Mercs (900302 etc)')
		self.channels['miexchng']=GGPOChannel("miexchng", "miexchng", 'Money Puzzle Exchanger', '', 1096)
		self.channels['mmancp2u']=GGPOChannel("mmancp2u", "mmancp2u", 'Mega Man - The Power Battle (951006 USA, SAMPLE Version)', '', 376)
		self.channels['mmatrix']=GGPOChannel("mmatrix", "mmatrix", 'Mars Matrix (000412 USA)')
		self.channels['mpang']=GGPOChannel("mpang", "mpang", 'Mighty! Pang (001010 USA)')
		self.channels['ms5plus']=GGPOChannel("ms5plus", "ms5plus", 'Metal Slug 5 Plus (bootleg)', '', 1096)
		self.channels['msh']=GGPOChannel("msh", "msh", 'Marvel Super Heroes (951024 Euro)')
		self.channels['mshvsf']=GGPOChannel("mshvsf", "mshvsf", 'Marvel Super Heroes vs Street Fighter (970625 Euro)', '', 376)
		self.channels['mslug2']=GGPOChannel("mslug2", "mslug2", 'Metal Slug 2 - super vehicle-001/II')
		self.channels['mslug3']=GGPOChannel("mslug3", "mslug3", 'Metal Slug 3', '', 1096)
		self.channels['mslug4']=GGPOChannel("mslug4", "mslug4", 'Metal Slug 4', '', 1096)
		self.channels['mslug3b6']=GGPOChannel("mslug3b6", "mslug3b6", 'Metal Slug 6 [Bootleg, bootleg of "Metal Slug 3"]', '', 1096)
		self.channels['mslug']=GGPOChannel("mslug", "mslug", 'Metal Slug - super vehicle-001', '', 1096)
		self.channels['mslugx']=GGPOChannel("mslugx", "mslugx", 'Metal Slug X - super vehicle-001', '', 1096)
		self.channels['msword']=GGPOChannel("msword", "msword", 'Magic Sword - heroic fantasy (25.07.1990 other country)')
		self.channels['mutnat']=GGPOChannel("mutnat", "mutnat", 'Mutation Nation')
		self.channels['mvsc']=GGPOChannel("mvsc", "mvsc", 'Marvel vs Capcom - clash of super heroes (980112 Euro)', '', 376)
		self.channels['ncombat']=GGPOChannel("ncombat", "ncombat", 'Ninja Combat (set 1)')
		self.channels['ncommand']=GGPOChannel("ncommand", "ncommand", 'Ninja Commando')
		self.channels['neobombe']=GGPOChannel("neobombe", "neobombe", 'Neo Bomberman', '', 1096)
		self.channels['neocup98']=GGPOChannel("neocup98", "neocup98", "Neo-Geo Cup '98 - the road to the victory")
		self.channels['neodrift']=GGPOChannel("neodrift", "neodrift", 'Neo Drift Out - new technology')
		self.channels['ninjamas']=GGPOChannel("ninjamas", "ninjamas", "Ninja Master's haoh ninpo cho", '', 1096)
		self.channels['nitd']=GGPOChannel("nitd", "nitd", 'Nightmare in the Dark')
		self.channels['nwarr']=GGPOChannel("nwarr", "nwarr", "Night Warriors - darkstalkers' revenge (950316 Euro)")
		self.channels['orlegend']=GGPOChannel("orlegend", "orlegend", 'Oriental Legend')
		self.channels['overtop']=GGPOChannel("overtop", "overtop", 'OverTop')
		self.channels['panicbom']=GGPOChannel("panicbom", "panicbom", 'Panic Bomber')
		self.channels['pbobbl2n']=GGPOChannel("pbobbl2n", "pbobbl2n", 'Puzzle Bobble 2', '', 1096)
		self.channels['pbobblen']=GGPOChannel("pbobblen", "pbobblen", 'Puzzle Bobble (set 1)')
		self.channels['pgoal']=GGPOChannel("pgoal", "pgoal", 'Pleasure Goal - 5 on 5 mini soccer')
		self.channels['preisle2']=GGPOChannel("preisle2", "preisle2", 'Prehistoric Isle 2')
		self.channels['progear']=GGPOChannel("progear", "progear", 'Progear (010117 USA)', '', 376)
		self.channels['pspikes2']=GGPOChannel("pspikes2", "pspikes2", 'Power Spikes II', '', 1096)
		self.channels['pulstar']=GGPOChannel("pulstar", "pulstar", 'Pulstar')
		self.channels['punisher']=GGPOChannel("punisher", "punisher", 'The Punisher (930422 etc)', '', 496)
		self.channels['pzloop2']=GGPOChannel("pzloop2", "pzloop2", 'Puzz Loop 2 (010302 Euro)')
		self.channels['ragnagrd']=GGPOChannel("ragnagrd", "ragnagrd", 'Ragnagard')
		self.channels['rbff1']=GGPOChannel("rbff1", "rbff1", 'Real Bout Fatal Fury', '', 1096)
		self.channels['rbff2']=GGPOChannel("rbff2", "rbff2", 'Real Bout Fatal Fury 2 - the newcomers (set 1)', '', 1096)
		self.channels['rbffspec']=GGPOChannel("rbffspec", "rbffspec", 'Real Bout Fatal Fury Special', '', 1096)
		self.channels['redeartn']=GGPOChannel("redeartn", "redeartn", 'Red Earth')
		self.channels['ridhero']=GGPOChannel("ridhero", "ridhero", 'Riding Hero (set 1)')
		self.channels['ringdest']=GGPOChannel("ringdest", "ringdest", 'Ring of Destruction - slammasters II (940902 Euro)', '', 496)
		self.channels['rotd']=GGPOChannel("rotd", "rotd", 'Rage of the Dragons', '', 1096)
		self.channels['s1945p']=GGPOChannel("s1945p", "s1945p", 'Strikers 1945 plus')
		#self.channels['sailormn']=GGPOChannel("sailormn", "sailormn", 'Pretty Soldier Sailor Moon (version 95/03/22B)')
		self.channels['samsh5sp']=GGPOChannel("samsh5sp", "samsh5sp", 'Samurai Shodown V Special (set 1, uncensored)', '', 1096)
		self.channels['samsho2']=GGPOChannel("samsho2", "samsho2", 'Samurai Shodown II', '', 1096)
		self.channels['samsho3']=GGPOChannel("samsho3", "samsho3", 'Samurai Shodown III (set 1)')
		self.channels['samsho4']=GGPOChannel("samsho4", "samsho4", "Samurai Shodown IV - Amakusa's revenge", '', 1096)
		self.channels['samsho5']=GGPOChannel("samsho5", "samsho5", 'Samurai Shodown V (set 1)')
		self.channels['samsho']=GGPOChannel("samsho", "samsho", 'Samurai Shodown')
		self.channels['savagere']=GGPOChannel("savagere", "savagere", 'Savage Reign')
		self.channels['sdodgeb']=GGPOChannel("sdodgeb", "sdodgeb", 'Super Dodge Ball', '', 1096)
		self.channels['sengoku2']=GGPOChannel("sengoku2", "sengoku2", 'Sengoku 2', '', 1096)
		self.channels['sengoku3']=GGPOChannel("sengoku3", "sengoku3", 'Sengoku 3')
		self.channels['sengoku']=GGPOChannel("sengoku", "sengoku", 'Sengoku (set 1)')
		self.channels['sf2ce']=GGPOChannel("sf2ce", "sf2ce", "Street Fighter II' - champion edition (street fighter 2' 920313 etc)", '', 736)
		self.channels['sf2hf']=GGPOChannel("sf2hf", "sf2hf", "Street Fighter II' - hyper fighting (street fighter 2' T 921209 ETC)", '', 736)
		self.channels['sf2koryu']=GGPOChannel("sf2koryu", "sf2koryu", "Street Fighter II' - champion edition (Hack - kouryu) [Bootleg]", '', 736)
		self.channels['sfa2']=GGPOChannel("sfa2", "sfa2", 'Street Fighter Alpha 2 (960306 USA)', '', 376)
		self.channels['sfa3']=GGPOChannel("sfa3", "sfa3:sfa3u", 'Street Fighter Alpha 3 (980904 Euro)', '', 376)
		self.channels['sfa']=GGPOChannel("sfa", "sfa", "Street Fighter Alpha - warriors' dreams (950727 Euro)", '', 376)
		self.channels['sfiii2n']=GGPOChannel("sfiii2n", "sfiii2n", 'Street Fighter III 2nd Impact: Giant Attack (Asia 970930, NO CD)', '', 496)
		self.channels['sfiii3n']=GGPOChannel("sfiii3n", "sfiii3n", 'Street Fighter III 3rd Strike: Fight for the Future (Japan 990512, NO CD)', '', 496)
		self.channels['sfiii3an']=GGPOChannel("sfiii3an", "sfiii3an", 'Street Fighter III 4th Strike (Hack) [bootleg]')
		#self.channels['sfiii3']=GGPOChannel("sfiii3", "sfiii3n", "Street Fighter Tres")
		#self.channels['sfiii']=GGPOChannel("sfiii", "sfiii", 'Street Fighter III: New Generation (Japan 970204)')
		self.channels['sfiiin']=GGPOChannel("sfiiin", "sfiiin", 'Street Fighter III: New Generation (Asia 970204, NO CD)', '', 496)
		self.channels['sfz2aa']=GGPOChannel("sfz2aa", "sfz2aa", 'Street Fighter Zero 2 Alpha (960826 Asia)')
		#self.channels['sfz2a']=GGPOChannel("sfz2a", "sfz2aa", "Street Fighter Alpha 2 Gold")
		self.channels['sgemf']=GGPOChannel("sgemf", "sgemf", 'Super Gem Fighter Mini Mix (970904 USA)', '', 376)
		self.channels['shocktr2']=GGPOChannel("shocktr2", "shocktr2", 'Shock Troopers - 2nd squad')
		self.channels['shocktro']=GGPOChannel("shocktro", "shocktro", 'Shock Troopers (set 1)')
		self.channels['slammast']=GGPOChannel("slammast", "slammast", 'Saturday Night Slam Masters (Slam Masters 930713 etc)', '', 496)
		#self.channels['snowbros']=GGPOChannel("snowbros", "snowbros", 'Snow Bros. - Nick & Tom (set 1)', '', 736)
		self.channels['sonicwi2']=GGPOChannel("sonicwi2", "sonicwi2", 'Aero Fighters 2')
		self.channels['sonicwi3']=GGPOChannel("sonicwi3", "sonicwi3", 'Aero Fighters 3')
		self.channels['spf2t']=GGPOChannel("spf2t", "spf2t", 'Super Puzzle Fighter II Turbo (Super Puzzle Fighter 2 Turbo 960620 USA)', '', 376)
		self.channels['spinmast']=GGPOChannel("spinmast", "spinmast", 'Spin Master')
		self.channels['ssf2']=GGPOChannel("ssf2", "ssf2", 'Super Street Fighter II - the new challengers (super street fighter 2 930911 etc)', '', 376)
		#self.channels['ssf2t']=GGPOChannel("ssf2t", "ssf2t", 'Super Street Fighter II Turbo (super street fighter 2 X 940223 etc)', '', 376)
		self.channels['ssf2xj']=GGPOChannel("ssf2xj", "ssf2xj", 'Super Street Fighter II X - grand master challenge (super street fighter 2 X 940223 Japan)', '', 376)
		self.channels['ssideki2']=GGPOChannel("ssideki2", "ssideki2", 'Super Sidekicks 2 - the world championship', '', 1096)
		self.channels['ssideki3']=GGPOChannel("ssideki3", "ssideki3", 'Super Sidekicks 3 - the next glory', '', 1096)
		self.channels['ssideki4']=GGPOChannel("ssideki4", "ssideki4", 'The Ultimate 11 - SNK football championship')
		self.channels['ssideki']=GGPOChannel("ssideki", "ssideki", 'Super Sidekicks')
		self.channels['strhoop']=GGPOChannel("strhoop", "strhoop", 'Street Hoop', '', 1096)
		self.channels['strider']=GGPOChannel("strider", "strider", 'Strider (US set 1)')
		#self.channels['svc']=GGPOChannel("svc", "svc", 'SvC Chaos - SNK vs Capcom (MVS)', '', 1096)
		self.channels['svcplus']=GGPOChannel("svcplus", "svcplus", 'SvC Chaos - SNK vs Capcom Plus (bootleg, set 1)', '', 1096)
		self.channels['theroes']=GGPOChannel("theroes", "theroes", 'Thunder Heroes')
		self.channels['tophuntr']=GGPOChannel("tophuntr", "tophuntr", 'Top Hunter - Roddy & Cathy (set 1)')
		self.channels['turfmast']=GGPOChannel("turfmast", "turfmast", 'Neo Turf Masters', '', 1096)
		self.channels['twinspri']=GGPOChannel("twinspri", "twinspri", 'Twinklestar Sprites', '', 1096)
		self.channels['tws96']=GGPOChannel("tws96", "tws96", "Tecmo World Soccer '96", '', 1096)
		self.channels['unsupported']=GGPOChannel("unsupported", "unsupported", "Unsupported Games", '', 1096)
		self.channels['uopoko']=GGPOChannel("uopoko", "uopoko", 'Puzzle Uo Poko (International)')
		self.channels['varth']=GGPOChannel("varth", "varth", 'Varth - operation thunderstorm (920714 etc)')
		self.channels['vhunt2']=GGPOChannel("vhunt2", "vhunt2", 'Vampire Hunter 2 - darkstalkers revenge (970929 Japan)')
		self.channels['vsav2']=GGPOChannel("vsav2", "vsav2", 'Vampire Savior 2 - the lord of vampire (970913 Japan)', '', 376)
		self.channels['vsav']=GGPOChannel("vsav", "vsav", 'Vampire Savior - the lord of vampire (970519 Euro)', '', 376)
		self.channels['wakuwak7']=GGPOChannel("wakuwak7", "wakuwak7", 'Waku Waku 7', '', 1096)
		self.channels['wh1']=GGPOChannel("wh1", "wh1", 'World Heroes (set 1)')
		self.channels['wh2']=GGPOChannel("wh2", "wh2", 'World Heroes 2')
		self.channels['wh2j']=GGPOChannel("wh2j", "wh2j", 'World Heroes 2 Jet (set 1)', '', 1096)
		self.channels['whp']=GGPOChannel("whp", "whp", 'World Heroes Perfect', '', 1096)
		self.channels['willow']=GGPOChannel("willow", "willow", 'Willow (US)', '', 736)
		self.channels['wjammers']=GGPOChannel("wjammers", "wjammers", 'Windjammers - flying disc game', '', 1096)
		self.channels['wof']=GGPOChannel("wof", "wof", 'Warriors of Fate (921002 etc)')
		self.channels['xmcota']=GGPOChannel("xmcota", "xmcota", 'X-Men - children of the atom (950105 Euro)', '', 376)
		self.channels['xmvsf']=GGPOChannel("xmvsf", "xmvsf", 'X-Men vs Street Fighter (961004 Euro)', '', 376)
		self.clients = {}  # Connected authenticated clients (GGPOClient instances) by nickname
		self.connections = {} # Connected unauthenticated clients (GGPOClient instances) by host
		self.quarks = {} # quark games (GGPOQuark instances) by quark
		SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)

class RendezvousUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
	def __init__(self, server_address, MyUDPHandler):
		self.quarkqueue = {}
		SocketServer.UDPServer.__init__(self, server_address, MyUDPHandler)

class MyUDPHandler(SocketServer.BaseRequestHandler):
	"""
	This class works similar to the TCP handler class, except that
	self.request consists of a pair of data and client socket, and since
	there is no connection the client address must be given explicitly
	when sending data back via sendto().
	"""

	def __init__(self, request, client_address, server):
		self.quark=''
		SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

	def addr2bytes(self, addr ):
		"""Convert an address pair to a hash."""
		host, port = addr
		try:
			host = socket.gethostbyname( host )
		except (socket.gaierror, socket.error):
			raise ValueError, "invalid host"
		try:
			port = int(port)
		except ValueError:
			raise ValueError, "invalid port"
		bytes  = socket.inet_aton( host )
		bytes += struct.pack( "H", port )
		return bytes

	def handle(self):
		data = self.request[0].strip()
		sockfd = self.request[1]

		if "useports" in data:
			quark=data.split("/")[1]
			quarkobject = ggposerver.quarks.setdefault(quark, GGPOQuark(quark))
			quarkobject.useports=True
			#ggposerver.quarks[quark].useports=True
			logging.info("[%s:%d] HOLEPUNCH FAILED for quark %s, will use ports" % (self.client_address[0], self.client_address[1], quark))

		if data != "ok" and "useports" not in data:
			try:
				self.quark, port = data.split('/')
			except ValueError:
				self.quark = data
				port=7001
			clientip=self.client_address[0]
			quarkobject = ggposerver.quarks.setdefault(self.quark, GGPOQuark(self.quark))
			quarkobject.proxyport[clientip]=port
			sockfd.sendto( "ok "+self.quark, self.client_address )
			logging.info("[%s:%d] HOLEPUNCH request received for quark: %s" % (self.client_address[0], self.client_address[1], self.quark))

		try:
			a, b = self.server.quarkqueue[self.quark], self.client_address
			sockfd.sendto( self.addr2bytes(a), b )
			sockfd.sendto( self.addr2bytes(b), a )
			logging.info("HOLEPUNCH linked: %s" % self.quark)
			del self.server.quarkqueue[self.quark]
		except KeyError:
			if self.quark!='':
				self.server.quarkqueue[self.quark] = self.client_address

class Daemon:
	"""
	Daemonize the current process (detach it from the console).
	"""

	def __init__(self):
		# Fork a child and end the parent (detach from parent)
		try:
			pid = os.fork()
			if pid > 0:
				sys.exit(0) # End parent
		except OSError, e:
			sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
			sys.exit(-2)

		# Change some defaults so the daemon doesn't tie up dirs, etc.
		os.setsid()
		os.umask(0)

		# Fork a child and end parent (so init now owns process)
		try:
			pid = os.fork()
			if pid > 0:
				try:
					f = file('ggposrv.pid', 'w')
					f.write(str(pid))
					f.close()
				except IOError, e:
					logging.error(e)
					sys.stderr.write(repr(e))
				sys.exit(0) # End parent
		except OSError, e:
			sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
			sys.exit(-2)

		# Close STDIN, STDOUT so we don't tie up the controlling terminal
		for fd in (0, 1):
			try:
				os.close(fd)
			except OSError:
				pass

if __name__ == "__main__":

	global holepunch, ggposerver

	print "-!- FightCade server version {0:.2f}".format(VERSION/100.0)
	print "-!- (c) 2014 Pau Oliva Fora (@pof) "

	#
	# Parameter parsing
	#
	parser = optparse.OptionParser()
	parser.set_usage(sys.argv[0] + " [option]")

	parser.add_option("--start", dest="start", action="store_true", default=True, help="Start ggposrv (default)")
	parser.add_option("--stop", dest="stop", action="store_true", default=False, help="Stop ggposrv")
	parser.add_option("--restart", dest="restart", action="store_true", default=False, help="Restart ggposrv")
	parser.add_option("-a", "--address", dest="listen_address", action="store", default='0.0.0.0', help="IP to listen on")
	parser.add_option("-p", "--port", dest="listen_port", action="store", default='7000', help="Port to listen on")
	parser.add_option("-V", "--verbose", dest="verbose", action="store_true", default=False, help="Be verbose (show lots of output)")
	parser.add_option("-l", "--log-stdout", dest="log_stdout", action="store_true", default=False, help="Also log to stdout")
	parser.add_option("-f", "--foreground", dest="foreground", action="store_true", default=False, help="Do not go into daemon mode.")
	parser.add_option("-H", "--http", dest="httpserver", action="store_true", default=False, help="Start debug http server on port 8000")
	parser.add_option("-u", "--udpholepunch", dest="udpholepunch", action="store_true", default=False, help="Use UDP hole punching.")

	(options, args) = parser.parse_args()

	holepunch=options.udpholepunch

	# Paths
	logfile = os.path.join(os.path.realpath(os.path.dirname(sys.argv[0])),'ggposrv.log')

	#
	# Logging
	#
	if options.verbose:
		loglevel = logging.DEBUG
	else:
		loglevel = logging.INFO

	log = logging.basicConfig(
		level=loglevel,
		format='%(asctime)s:%(levelname)s:%(message)s',
		filename=logfile,
		filemode='a')

	#
	# Handle start/stop/restart commands.
	#
	if options.stop or options.restart:
		print "-!- Stopping ggposrv"
		logging.info("Stopping ggposrv")
		pid = None
		try:
			f = file('ggposrv.pid', 'r')
			pid = int(f.readline())
			f.close()
			os.unlink('ggposrv.pid')
		except ValueError, e:
			sys.stderr.write('Error in pid file `ggposrv.pid`. Aborting\n')
			sys.exit(-1)
		except IOError, e:
			pass

		if pid:
			os.kill(pid, 15)
		else:
			sys.stderr.write('ggposrv not running or no PID file found\n')

		if not options.restart:
			sys.exit(0)

	print "-!- Starting ggposrv"
	logging.info("Starting ggposrv")
	logging.debug("logfile = %s" % (logfile))

	if options.log_stdout:
		console = logging.StreamHandler()
		formatter = logging.Formatter('[%(levelname)s] %(message)s')
		console.setFormatter(formatter)
		console.setLevel(logging.DEBUG)
		logging.getLogger('').addHandler(console)

	if options.verbose:
		logging.info("We're being verbose")

	# set the thread stack size, by default it uses the operating system value found by 'ulimit -s' = 8192 kbytes (8Mb).
	# the minimum value here is 32768 (32kB), and ideally should be multiple of 4096. For example 524288 = 512kb
	# With the default value of 8192 kB (8Mb) I can create around 300 threads. Setting it to 2Mb and see what happens..
	threading.stack_size(4096*512)

	#
	# Go into daemon mode
	#
	if not options.foreground:
		Daemon()

	#
	# Start server
	#
	try:

		if holepunch:
			punchserver = RendezvousUDPServer((options.listen_address, int(options.listen_port)), MyUDPHandler)
			logging.info('Starting holepunch on %s:%s/udp' % (options.listen_address, options.listen_port))
			t = threading.Thread(target=punchserver.serve_forever)
			t.daemon = True
			t.start()

		ggposerver = GGPOServer((options.listen_address, int(options.listen_port)), GGPOClient)
		logging.info('Starting ggposrv on %s:%s/tcp' % (options.listen_address, options.listen_port))

		if options.httpserver:
			webserver = HTTPServer((options.listen_address, 8000), GGPOHttpHandler)
			logging.info('Starting http server on %s:8000/tcp' % (options.listen_address))
			t2=threading.Thread(target=webserver.serve_forever)
			t2.daemon=True
			t2.start()

		ggposerver.serve_forever()

	except socket.error, e:
		logging.error(repr(e))
		sys.exit(-2)
	except:
		traceback.print_exc(file=open("ggposrv-errors.log","a"))
