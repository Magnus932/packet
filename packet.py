
import _packet
import random
import time
from socket import socket, AF_PACKET, SOCK_RAW, \
	IPPROTO_RAW

PROTO_ARP			=		0x0806
PROTO_IP			=		0x0800
PROTO_IPV6			=		0x86dd
PROTO_ICMP			=		0x0001
PROTO_TCP			=		0x0006
PROTO_UDP			=		0x0011

ARP_HW_TYPE_ETHER	=		0x0001
ARP_REQUEST			=		0x0001
ARP_REPLY			=		0x0002

class ppcap(_packet.ppcap):
	def __init__(self):
		_packet.ppcap.__init__(self)

	def next(self):
		while True:
			time.sleep(0.010)
			packet = _packet.ppcap.next(self)
			if (not packet): continue
			return packet

class Sender:
	def __init__(self):
		self.sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)

	def sendto(self, data, destination):
		self.sock.sendto(data, destination)
'''
	These classes works as wrappers around
	the type objects. They make it easier to
	send raw packets by just providing a few
	fields. The rest of the fields are filled to
	generic values. After initializing an object
	the user should always call 'obj.calc_len'
	and 'obj.calc_csum' in that order on protocol
	types that are >= PROTO_IP, unless you want to fill
	these fields yourself.
'''
class ARPGenericPacket(_packet.arp, Sender):
	def __init__(self, args):
		Sender.__init__(self)
		if (args):
			for i in args:
				if "ip_source" in i:
					self.arp_src_ip = args[i]
				if "ip_dest" in i:
					self.arp_dst_ip = args[i]
				if "mac_src" in i:
					self.ethernet_src = args[i]
					self.arp_src_mac = args[i]
				if "mac_dst" in i:
					self.ethernet_dst = args[i]
					self.arp_dst_mac = args[i]
		self.ethernet_type = PROTO_ARP
		# Assign default ARP fields for a request
		self.arp_hw_type = ARP_HW_TYPE_ETHER
		self.arp_proto = PROTO_IP
		self.arp_hw_size = 6
		self.arp_proto_size = 4

class ARPRequestPacket(ARPGenericPacket):
	def __init__(self, args=None):
		if (type(args) != dict and args):
			raise TypeError("args needs to be of type 'dict'")
		ARPGenericPacket.__init__(self, args)
		self.arp_opcode = ARP_REQUEST

class ARPReplyPacket(ARPGenericPacket):
	def __init__(self, args=None):
		if (type(args) != dict and args):
			raise TypeError("args needs to be of type 'dict'")
		ARPGenericPacket.__init__(self, args)
		self.arp_opcode = ARP_REPLY

class UDPPacket(_packet.udp, Sender):
	def __init__(self, args=None):
		if (type(args) != dict and args):
			raise TypeError("args needs to be of type 'dict'")
		Sender.__init__(self)
		if (args):
			for i in args:
				if "udp_src" in i:
					self.udp_src = args[i]
				if "udp_dst" in i:
					self.udp_dst = args[i]
				if "ip_source" in i:
					self.ip_source = args[i]
				if "ip_dest" in i:
					self.ip_dest = args[i]
				if "mac_src" in i:
					self.ethernet_src = args[i]
				if "mac_dst" in i:
					self.ethernet_dst = args[i]
				if "payload" in i:
					self.udp_payload = args[i]
		# Assign default ethernet fields.
		self.ethernet_type = PROTO_IP
		# Assign default IP fields.
		self.ip_hlen = 5
		self.ip_version = 4
		self.ip_dsf = 0
		self.ip_identifier = random.randrange(3000)
		self.ip_frag_off = 0
		self.ip_ttl = 255
		self.ip_proto = PROTO_UDP
		self.ip_csum = 0
		# Assign default UDP fields.
		self.udp_csum = 0

class TCPPacket(_packet.tcp, Sender):
	def __init__(self, args=None):
		if (type(args) != dict and args):
			raise TypeError("args needs to be of type 'dict'")
		Sender.__init__(self)
		if (args):
			for i in args:
				if "tcp_src" in i:
					self.tcp_src = args[i]
				if "tcp_dst" in i:
					self.tcp_dst = args[i]
				if "ip_source" in i:
					self.ip_source = args[i]
				if "ip_dest" in i:
					self.ip_dest = args[i]
				if "mac_src" in i:
					self.ethernet_src = args[i]
				if "mac_dst" in i:
					self.ethernet_dst = args[i]
				if "tcp_seq" in i:
					self.tcp_seq = args[i]
				if "tcp_seq_ack" in i:
					self.tcp_seq_ack = args[i]
				if "payload" in i:
					self.tcp_payload = args[i]
		# Assign default ethernet fields.
		self.ethernet_type = PROTO_IP
		# Assign default IP fields.
		self.ip_hlen = 5
		self.ip_version = 4
		self.ip_dsf = 0
		self.ip_identifier = random.randrange(3000)
		self.ip_frag_off = 0
		self.ip_ttl = 255
		self.ip_proto = PROTO_TCP
		self.ip_csum = 0
		# Assign default TCP fields.
		self.tcp_hlen = 5 # 5 << 2 == 20
		self.tcp_win = 44200
		self.tcp_csum = 0
		self.tcp_urg_ptr = 0

'''
	Creating deeper functionality on top of these
	wrappers can consist of; ARP spoofers, ARP scanners,
	TCP hijackers that pipes the data to an SSL decrypter/encrypter
	or maybe just some fun UDP packets that crash a game, just for
	the kicks of it. All of the above methods are an ease just filling
	out a few fields in a dictionary type before typing obj.sendto(...)
	combining both a packet capturer and a raw packet.

	A simple UDP example is provided below;

	args = {
		"udp_src" 	: 1000,
		"udp_dst" 	: 2000,
		"ip_source"	: "XXXXXXXXXXX",
		"ip_dest" 	: "XXXXXXXXXXX",
		"mac_src"	: (0xXX, 0xXX, 0xXX, 0xXX, 0xXX, 0xXX),
		"mac_dst"	: (0xXX, 0xXX, 0xXX, 0xXX, 0xXX, 0xXX),
		"payload"	: b"Hello world from packet"
	}
	obj = UDPPacket(args)
	obj.calc_len()
	obj.calc_csum()
	obj.sendto(obj.to_bytes(), ("device", 0))
'''
