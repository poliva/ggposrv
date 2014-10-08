#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# open source ggpo server (re)implementation
# 
#  (c) 2014 Pau Oliva Fora (@pof)
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
import multiprocessing
import socket
import struct
from threading import Thread

q = multiprocessing.Queue()
nick = ''
status = 0
DEBUG=False

def pad2hex(l):
	return "".join(reversed(struct.pack('I',l)))

def sizepad(value):
	l=len(value)
	pdu = pad2hex(l)
	pdu += value
	return pdu

def reply(sequence,pdu,connection):

	length=4+len(pdu)
	connection.sendall(pad2hex(length) + pad2hex(sequence) + pdu)
	if (DEBUG): print ("SENT DATA:", pad2hex(length) + pad2hex(sequence) + pdu)

def parse(data,connection,address):
	global nick,status

	if (DEBUG): print ("DATA:", data)

	length=int(data[0:4].encode('hex'),16)
	if (DEBUG): print ("LEN:", length)

	if (length >= 4):
		sequence=int(data[4:8].encode('hex'),16)
		if (DEBUG): print ("SEQ:", sequence)

		if (sequence==1):
			reply(sequence,'\x00\x00\x00\x00',connection)

	if (length >= 8):
		command=int(data[8:12].encode('hex'),16)
		if (DEBUG): print("command:", command)

		if (command==1):
			nicklen=int(data[12:16].encode('hex'),16)
			nick=data[16:16+nicklen]
			if (DEBUG): print ("NICK:",nick)
			# auth successful
			reply(sequence,'\x00\x00\x00\x00',connection)
			negseq=4294967293 #'\xff\xff\xff\xfd'
			pdu='\x00\x00\x00\x02'
			pdu+='\x00\x00\x00\x01'
			pdu+=sizepad(nick)
			pdu+=pad2hex(status) #status
			pdu+='\x00\x00\x00\x00' #p2(?)
			pdu+=sizepad(str(address[0]))
			pdu+='\x00\x00\x00\x00' #unk1
			pdu+='\x00\x00\x00\x00' #unk2
			pdu+=sizepad("City")
			pdu+=sizepad("CC")
			pdu+=sizepad("Country")
			pdu+=pad2hex(6009)      # port
			pdu+='\x00\x00\x00\x01' # ?
			pdu+=sizepad(nick)
			pdu+=pad2hex(status) #status
			pdu+='\x00\x00\x00\x00' #p2(?)
			pdu+=sizepad(str(address[0]))
			pdu+='\x00\x00\x00\x00' #unk1
			pdu+='\x00\x00\x00\x00' #unk2
			pdu+=sizepad("City")
			pdu+=sizepad("CC")
			pdu+=sizepad("Country")
			pdu+=pad2hex(6009)      # port
			reply(negseq,pdu,connection)
			negseq=4294967295
			reply(negseq,'',connection)
		if (command==2): # motd
		# pdu length + seqnum + 00 00 00 00 + sizeofchannelname + channelname + sizeofchanneldesc + channeldesc + sizeofmotd + motd
			reply(sequence,'\x00\x00\x00\x00'+sizepad("ssf2t")+sizepad("Super Street Fighter II: Turbo")+sizepad("Thanks papasi.\n"),connection)
		
		if (command==3): # list
			pdu=''
			channels=(('game1','game1','game one'),
				('game2','game2','game two'),
				('ssf2t','ssf2t','Super Street Fighter II: Turbo'))
			i=0
			for channel in channels:
				i=i+1
				pdu+=sizepad(channel[0])
				pdu+=sizepad(channel[1])
				pdu+=sizepad(channel[2])
				pdu+=pad2hex(i)
			
			reply(sequence,'\x00\x00\x00\x00'+pad2hex(i)+pdu,connection)

		if (command==4): # users
			# pdu length + seqnum + 00 00 00 00 + num users +
			# nicklen + nick + status + p2len + (p2nick) + iplen + ip + unk1 + unk2 + citylen + city + cc_len + cc + countrylen + country +port
			# if p2len==0 p2nick is null
			pdu=''
			users=((nick,status,'null',str(address[0]),'City','CC','Country','6009'),
				('user1','0','null','1.2.3.4','Madrid','ES','Spain','6009'),
				('user3','2','user4','7.8.3.1','Tokyo','JP','Japan','6009'),
				('user4','2','user3','7.7.3.2','Paris','FR','France','6009'),
				('user2','1','null','5.4.3.2','San Francisco','US','United States','6009'))

			i=0
			for user in users:
				i=i+1
				pdu+=sizepad(user[0])
				pdu+=pad2hex(int(user[1]))
				if (user[2]!="null"):
					pdu+=sizepad(user[2])
				else:
					pdu+='\x00\x00\x00\x00'
				pdu+=sizepad(user[3])
				pdu+='\x00\x00\x00\x00' #unk1
				pdu+='\x00\x00\x00\x00' #unk2
				pdu+=sizepad(user[4])
				pdu+=sizepad(user[5])
				pdu+=sizepad(user[6])
				pdu+=pad2hex(int(user[7]))

			reply(sequence,'\x00\x00\x00\x00'+pad2hex(i)+pdu,connection)

		if (command==6): # change status (0: available, 1: away..)
			status=int(data[12:16].encode('hex'),16)
			reply(sequence,'\x00\x00\x00\x00',connection)
			negseq=4294967293 #'\xff\xff\xff\xfd'
			pdu='\x00\x00\x00\x01'
			pdu+='\x00\x00\x00\x01'
			pdu+=sizepad(nick)
			pdu+=pad2hex(status) #status
			pdu+='\x00\x00\x00\x00' #p2(?)
			pdu+=sizepad(str(address[0]))
			pdu+='\x00\x00\x00\x00' #unk1
			pdu+='\x00\x00\x00\x00' #unk2
			pdu+=sizepad("City")
			pdu+=sizepad("CC")
			pdu+=sizepad("Country")
			pdu+=pad2hex(6009)      # port
			reply(negseq,pdu,connection)
		
		if (command==7): # chat
			msglen=int(data[12:16].encode('hex'),16)
			msg=data[16:16+msglen]
			q.put(msg)

	if (len(data) > length+4 ):
		pdu=data[length+4:]
		parse(pdu,connection,address)
		return

def datathread(connection,address):
	while True:
		while not q.empty():
			negseq=4294967294 #'\xff\xff\xff\xfe'
			msg=str(q.get())
			reply(negseq,sizepad(nick)+sizepad(msg),connection)

def handle(connection, address):
	try:
		if (DEBUG): print ("Connected", connection, "at", address)

		t = Thread(target=datathread, args=(connection, address))
        	t.daemon = False
        	t.start()

		while True:
			data = connection.recv(1024)
			if data == "":
				if (DEBUG): print ("Remote end closed connection")
				break
			if (DEBUG): print ("RECEIVED:", data)
			parse(data,connection,address)
	except:
		if (DEBUG): print ("Problem handling request")
	finally:
		print ("Connection finished")
		connection.close()

class Server(object):
	def __init__(self, hostname, port):
		self.hostname = hostname
		self.port = port
		#self.channels = {}
		#self.clients = {}

	def start(self):
		print ("Server listening")
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.bind((self.hostname, self.port))
		self.socket.listen(1)

		while True:
			conn, address = self.socket.accept()
			print ("New connection")
			process = multiprocessing.Process(target=handle, args=(conn, address))
			process.daemon = True
			process.start()

if __name__ == "__main__":
	server = Server("0.0.0.0", 7000)
	try:
		server.start()
	except:
		print ("Exception")
	finally:
		print("Shutting down")
	for process in multiprocessing.active_children():
		process.terminate()
		process.join()
