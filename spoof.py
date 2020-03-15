from scapy.all import *
import random

pay1 = "GET /EVIL"
pay2 = "STUFF HTTP/1.1\r\nHost: sender\r\n\r\n"

sp = random.randint(1024,65535)
destport = 50788
ip=IP(src="127.0.0.1", dst="127.0.0.1")

SYN=TCP(sport=sp, dport=8080, flags="S", seq=10)
SYNACK=sr1(ip/SYN)

my_ack = SYNACK.seq + 1
bad_ack = my_ack + 1

next_seq = SYN.seq + 1

ACK=TCP(ack=bad_ack, sport=sp, dport=8080, flags="A", seq=next_seq)
send(ip/ACK)

PUSH=TCP(ack=my_ack, seq=next_seq, sport=sp, dport=8080, flags="PA")
send(ip/PUSH/pay1)
next_seq = ACK.seq + len(pay1)

PUSH=TCP(ack=my_ack, seq=next_seq, sport=sp, dport=8080, flags="PA")
send(ip/PUSH/pay2)
next_seq = PUSH.seq + len(pay2)

RST=TCP(ack=my_ack, seq=next_seq, sport=sp, dport=8080, flags="RA")
send(ip/RST)