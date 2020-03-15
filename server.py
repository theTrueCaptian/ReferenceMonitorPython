from socket import *
import thread

import signal

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import MD5
import pickle
import os, base64
from Crypto.Cipher import AES
import hmac
import hashlib
from hashlib import sha1
import re

Users = [ ('Alice', 'maeda'), ('Bob', 'maeda'), ('Eve', 'evil'), ('Maeda', 'good'), ('Adam', 'good')]

IS_TCP = True

BUFF = 1024
HOST = '127.0.0.1'
PORT = 8080
MAX_CLIENTS = 10
CONNECTION_LIST = []
block_list = []


def close_handler(signum, frame):
	#This is called when the terminal session is closed
	serversocket.close()
	pass

def find_user(username, password):
	for person in Users:
		if person[0] == username and person[1] == password:
			return person
	return None

def isReadUser(username):
	for person in Users:
		if person[0] == username:
			return True
	return False
'''
def get_conn_info(username):
	for c in CONNECTION_LIST:
		if c['name'] == username:
			return c
	return None
'''
def isLoggedOn(username):
	for loggedon in CONNECTION_LIST:
		if loggedon['name'] == username:
			print username+ ' logged on'
			return True
	print username+ ' logged on'
	return False

#Returns true if user1 blocked user2
def isUserBlockedUser(user1, user2):
	for blocked in block_list:
		if blocked[0] == user1 and blocked[1] == user2:
			return True
	return False
'''
def isOnBlockList(username, block_list):
	for blocked in block_list:
		if blocked['name'] ==username:
			return True
	return False
'''	
#Safely close sockets when ctrl+c happens
# Otherwise this error would happen: http://stackoverflow.com/questions/19071512/socket-error-errno-48-address-already-in-use
#run> ps -fA | grep python
# kill <2nd num, proc num>
signal.signal( signal.SIGHUP, close_handler )

def broadcast_data (sock, message, originuser):
	#Do not send the message to master socket and the client who has send us the message
	for socket_info in CONNECTION_LIST:
		socket = socket_info['socket']
		if socket != serversocket and socket != sock and not isUserBlockedUser(socket_info['name'], originuser):  #and not isOnBlockList(socket_info['name'], block_list):
			try :
				socket.send(message)
			except :
				# broken socket connection may be, chat client pressed ctrl+c for example
				socket.close()

				CONNECTION_LIST.remove(socket_info)

#Call this when received
def client_handler(clientsocket, addr):

	#Establish session key with the client
	#Create keys and send the public key to client
	KEY_LENGTH = 1024  # Key size (in bits)
	random_gen = Random.new().read
	server_key = RSA.generate(KEY_LENGTH, random_gen)
	server_public  = server_key.publickey()
	clientsocket.sendto(pickle.dumps(server_public), ADDR)

	#Receive the client's publickey later on to be used for encryption 
	client_public = pickle.loads(clientsocket.recv(4096))
	print 'Received client '+str(addr)+' public key: '+str(client_public)

	#Encrypt the session key with the clien't public key and then send it to the client
	session_key = base64.b64encode(os.urandom(16))
	# Generate digital signatures using server private keys
	hash_session = MD5.new(session_key).digest()
	hash_signature = server_key.sign(hash_session, '')
	hash_encrypted = client_public.encrypt(session_key, 32) 
	tot_msg = (hash_encrypted, hash_signature)
	print 'Session key created for client '+str(addr)
	clientsocket.sendto(pickle.dumps(tot_msg), ADDR)

	#Authenticate the user. Decrypt with the session_key
	authorization_attempt = pickle.loads(clientsocket.recv(4096))
	auth_info = authorization_attempt[0]
	mac = authorization_attempt[1]
	expected_mac = hmac.new(session_key,auth_info,hashlib.sha1)
	if not hmac.compare_digest(expected_mac.hexdigest(), mac):
		print "\nWarning! The authentication information has been tampered with OR client didn't get the right session key."
		clientsocket.close()
	decryption_suite = AES.new(session_key, AES.MODE_CBC, 'This is an IV456')
	auth_decrypted = decryption_suite.decrypt(auth_info)
	split = auth_decrypted.split(';password=')
	username = split[0]
	password = split[1].rsplit(';', 1)[0]		#Remove the padding
	if find_user(username, password) is None or isLoggedOn(username):#(str(username), str(password)) not in Users:
		print 'Client '+str(clientsocket)+ ' is not authorized'
		clientsocket.close()
		return

	CONNECTION_LIST.append({'name': username, 'socket':clientsocket})

	#Send client information on the number
	clientsocket.send('Server>'+str(addr))
	print "Connected "+username+" from: "+str(addr)
	broadcast_data( clientsocket, "Server> Connected "+username+" from: "+str(addr), "SERVER")

	while 1:
		#Listen for data from client
		data = clientsocket.recv(1024)
		if not data:
			break
		print "Received Message: "+repr(data)

		#Decipher the messages and to check if it is a command
		data_message = data
		split = data_message.split(';hmac=')
		message = split[0]
		mac = split[1]
		expected_mac = hmac.new(session_key, message, hashlib.sha1)
		#Verify if it is meant for the server. Otherwise broadcast it
		if hmac.compare_digest(expected_mac.hexdigest(), mac):
			print 'Received server command from '+username
			decryption_suite = AES.new(session_key, AES.MODE_CBC, 'This is an IV456')
			server_command = decryption_suite.decrypt(message)
			server_command = server_command.rsplit(';', 1)[0]

			whole_message = ""
			if server_command.startswith('/onlineusers'): 	
				for connect in CONNECTION_LIST:
					if not isUserBlockedUser(connect['name'], username):
						whole_message = whole_message + connect['name'] + " ;"
				
			elif server_command.startswith('/block'):
				userToBlock = server_command.rsplit(' ', 2)[1]
				userToBlock = re.sub('[\\s]*', '', userToBlock)
				print "User to block:"+userToBlock+"|"
				#conn_info = get_conn_info(userToBlock) 
				if isReadUser(userToBlock):
					block_list.append((username, userToBlock))
					whole_message = userToBlock+" successfully blocked"
				else:
					whole_message = "Not an online user"
			else:
				whole_message = "Invalid commands! Commands: \n/onlineusers --> Get user online \n /block <username> --> Block person"
			#Encryption
			padding = (int)(float(16*(int)(len(whole_message)/16+1)))	# float(16*(int)(100/16+1)) = 112
			whole_message = whole_message.ljust(padding)
			encryption_suite = AES.new(session_key, AES.MODE_CBC, 'This is an IV456')
			cipher_text = encryption_suite.encrypt(whole_message)
			digest_maker = hmac.new(session_key,cipher_text,hashlib.sha1)
			final_message = cipher_text+';hmac='+digest_maker.hexdigest()
			clientsocket.send(final_message)
		else:
			broadcast_data(clientsocket, data, username)	
		
		

	clientsocket.close()

ADDR = (HOST, PORT)
if IS_TCP:
	serversocket = socket(AF_INET, SOCK_STREAM)
	serversocket.bind(ADDR)
	serversocket.listen(MAX_CLIENTS) 
	# Add server socket to the list of readable connections
	CONNECTION_LIST.append({'name':'SERVER', 'socket':serversocket})
else:
	serversocket = socket(AF_INET, SOCK_DGRAM)
	serversocket.bind(ADDR)

print "Listening at "+str(HOST)+":"+str(PORT)

#Continuously listen for incoming clients and then pass the handler to client_handler()
while 1:
	if IS_TCP:
		clientsocket, addr = serversocket.accept()

		thread.start_new_thread(client_handler, (clientsocket, addr))
		broadcast_data(clientsocket, "Server> "+str(addr)+"entered room\n", "SERVER" )

	else:
		data, addr = serversocket.recvfrom(4096)
		if addr not in CONNECTION_LIST:
			CONNECTION_LIST.append({'name':'' , 'socket':addr})
		print "Received Message from "+repr(addr)+": "+repr(data)+''
		#serversocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		#serversocket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
		
		for address in CONNECTION_LIST:
			serversocket.sendto(data, address.socket)


if IS_TCP:
	serversocket.close()