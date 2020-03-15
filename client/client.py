from socket import *
import sys
import select
import string
import thread
import socket
import select
import socket
import threading
import time
from Crypto.Cipher import AES
import hmac
import hashlib
from hashlib import sha1
from time import time
import re

import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import MD5

import pickle

IS_TCP = True
IS_CHECK_AUTH = True


HOST = '127.0.0.1'
PORT = 8080
ADDR = (HOST, PORT)


def chat_client():
	last_time_message = 0 

	#if(len(sys.argv) == 2) :
	#	print 'Usage : python chat_client.py hostname port'
	#	sys.exit()

	if IS_TCP:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(2)

		# connect to remote host
		try :
			s.connect(ADDR)
		except :
			print 'Unable to connect'
			sys.exit()
    
	else:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	 
	 
	 
	#Establish key session with the server
	#Receive the server's publickey later on to be used for encryption 
	server_public = pickle.loads(s.recv(4096))
	print 'Received server\'s public key: '+str(server_public)

	#Create keys and send the public key to server
	KEY_LENGTH = 1024  # Key size (in bits)
	random_gen = Random.new().read
	client_key = RSA.generate(KEY_LENGTH, random_gen)
	client_public  = client_key.publickey()
	s.sendto(pickle.dumps(client_public), ADDR)

	#Receive the session key from the server
	sessionkey_data = pickle.loads(s.recv(4096))
	#split = sessionkey_data.split(';hmac=')
	encrypted_sessionkey = sessionkey_data[0]
	server_signature = sessionkey_data[1]

	#Decrypt the session key with client's private key
	sessionkey   = client_key.decrypt(encrypted_sessionkey)

	#Verify the signature with the decreypted session key
	hash_decrypted = MD5.new(sessionkey).digest()
	if not server_public.verify(hash_decrypted, server_signature):
		print 'Session key is corrupted! Ending session now.'
		sys.exit()

	#Send in the authenication with symmetric encryption
	authentication_info = username+";password="+password+";"
	padding = (int)(float(16*(int)(len(authentication_info)/16+1)))	# float(16*(int)(100/16+1)) = 112
	authentication_info = authentication_info.ljust(padding)
	encryption_suite = AES.new(sessionkey, AES.MODE_CBC, 'This is an IV456')
	cipher_text = encryption_suite.encrypt(authentication_info)
	digest_maker = hmac.new(sessionkey,cipher_text,hashlib.sha1)
	final_message = (cipher_text, digest_maker.hexdigest())
	s.send(pickle.dumps(final_message))

	print 'Commands: \n/onlineusers --> Get user online \n /block <username> --> Block person'
	print 'Connected to remote host. You can start sending messages'
	sys.stdout.write(''); sys.stdout.flush()

	while 1:
		socket_list = [sys.stdin, s]
		 
		# Get the list sockets which are readable
		ready_to_read,ready_to_write,in_error = select.select(socket_list , [], [])
		 
		for sock in ready_to_read:             
			if sock == s:
				
				# incoming message from remote server, s
				if IS_TCP:
					data = sock.recv(4096)
				else:
					data, server = sock.recvfrom(4096)

				if not data :
					print '\nDisconnected from chat server'
					sys.exit()
				else :
					
					#Decrypt the message if the user has indicated password
					if data[0:7]!='Server>' and key!='' and IS_CHECK_AUTH:

						#Try decrypt with key i.e. the group chat key
						#If the verification with the key didn't work, then try with session key to see if it is message from the server
						#Read in the hmac
						split = data.split(';hmac=')
						data = split[0]
						mac = split[1]

						#Verify the mac on the data
						expected_mac = hmac.new(key,data,hashlib.sha1)
						if hmac.compare_digest(expected_mac.hexdigest(), mac):
							# Decryption
							decryption_suite = AES.new(key, AES.MODE_CBC, 'This is an IV456')
							plain_text = decryption_suite.decrypt(data)
							
							#Verify no one has replayed this message, by checking the timestamp and the current time
							matchObj = re.match( r'\[([0-9]+)\.*[0-9]*\].*', plain_text)
							if matchObj:
								#if the last time a message was received is greater than this message timestamp, then the message was replayed
								if long(matchObj.group(1))<last_time_message :
									print "And the message was also replayed."
								else:
									last_time_message = long(matchObj.group(1))
							
							sys.stdout.write('\n'+plain_text)

						else:
							#Try to decrypt with sessionkey; it might be server message
							expected_mac = hmac.new(sessionkey,data,hashlib.sha1)
							if hmac.compare_digest(expected_mac.hexdigest(), mac):
								decryption_suite = AES.new(sessionkey, AES.MODE_CBC, 'This is an IV456')
								plain_text = decryption_suite.decrypt(data)
							
								sys.stdout.write('\n'+plain_text)
							else:
								print "\nWarning! The following message has been tampered with OR you dont have the right key."

						
						

					else:
						#print data
						sys.stdout.write('\n'+data)
					
					sys.stdout.write('\n'); sys.stdout.flush()     


            
			else :
				# user entered a message
				msg = sys.stdin.readline()

				if key!='' and IS_CHECK_AUTH:
					#Encrypt messages with the session key if the message is for the server
					if isServerCommand(msg):
						whole_message = msg+";"
						padding = (int)(float(16*(int)(len(whole_message)/16+1)))	# float(16*(int)(100/16+1)) = 112
						whole_message = whole_message.ljust(padding)
						
						#Encryption
						encryption_suite = AES.new(sessionkey, AES.MODE_CBC, 'This is an IV456')
						cipher_text = encryption_suite.encrypt(whole_message)
						digest_maker = hmac.new(sessionkey,cipher_text,hashlib.sha1)
						final_message = cipher_text+';hmac='+digest_maker.hexdigest()
						s.send(final_message)
					else: 
						whole_message = "["+str(time())+"]"+username+">"+msg
						padding = (int)(float(16*(int)(len(whole_message)/16+1)))	# float(16*(int)(100/16+1)) = 112
						whole_message = whole_message.ljust(padding)
						
						#Encryption
						encryption_suite = AES.new(key, AES.MODE_CBC, 'This is an IV456')
						cipher_text = encryption_suite.encrypt(whole_message)
			
						digest_maker = hmac.new(key,cipher_text,hashlib.sha1)

						final_message = cipher_text+';hmac='+digest_maker.hexdigest()

						if IS_TCP:
							s.send(final_message)
						else:
							s.sendto(final_message, ADDR)
				else:

					#Do not encrypt if the user didn't specify anything for the password
					final_message = "["+str(time())+"]"+username+">"+msg
					if IS_TCP:
						s.send(final_message)
					else:
						s.sendto(final_message, ADDR)

				sys.stdout.write('Me>'+msg); sys.stdout.flush() 

#Returns true if the message is for the server
def isServerCommand(msg):
	if msg.startswith('/onlineusers') or msg.startswith('/block'):
		return True
	return False


if __name__ == "__main__":

	username = raw_input("\nUsername: ")

	#Prompt the key that will decode the messages
	key = raw_input("\nPassword: ")
	password = key 	#password is the non padded versus of password
	if key!='':
		padding = (int)(float(16*(int)(len(key)/16+1)))
		key = key.ljust(padding)

	
	sys.exit(chat_client())

