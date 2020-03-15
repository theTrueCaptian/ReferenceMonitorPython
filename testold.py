import unittest
import binascii
import aes
import numpy as np
np.set_printoptions(formatter={'int':hex})
import textwrap

INPUT_BLOCK_LEN = 128
shared_key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]

class GeneticTest(unittest.TestCase):
    def setUp(self):
        self.aes = AES.AES(
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])

	def test__encrypt(self):
		given = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
		expected = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x4, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]
		self.assertEqual(self.aes.encrypt(given), expected)

	def test__decrypt(self):
		expected = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
		given = [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x4, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]

		self.assertEqual(self.aes.decrypt(given), expected)


def convert2ascii(arr):
	'''
	Convert an array of hex, [0x6d, 0x69, 0x63] --> mic
	First it converts each element into binary of length 8 and then calling chr to convert to ascii
	Finally concats all and returns the string
	'''
	concat = map(lambda x:chr(int(bin(x)[2:].zfill(8), 2)), arr)
	return ''.join(concat)

message = "First it converts each element into binary of length 8 and then calling chr to convert to ascii"


#Turn the string length into a some multiple of 16
padding = 16-(len(message)%16)
factor16len = padding + len(message)
message = message.ljust(factor16len)

#Divide the message into blocks of 16 chars
messageblocks =  list(map(''.join, zip(*[iter(message)]*16)))
#messageblock = 'microprogramming'
for messageblock in messageblocks:
	print messageblock+"|"
	msg_hex =  map(lambda x: int(binascii.hexlify(x), 16), list(messageblock))
	cipher =  aes.AES(shared_key).encrypt(msg_hex)
	deciphered = aes.AES(shared_key).decrypt(cipher)
	print "messageblock:"+messageblock
	print "msg_hex:"+str(np.array(msg_hex))
	print "cipher:"+str(np.array(cipher)) 
	print "deciphered:"+str(np.array(deciphered))
	combined = convert2ascii(deciphered)
	print "final:"+combined

unittest.main()