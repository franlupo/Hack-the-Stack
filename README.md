# Hack-the-Stack
This repository contains a collection of Python scripts designed to assess and exploit programs that are susceptible to buffer overflow attacks.

### 1. Automatic Fuzzer

This is a Python script for fuzz testing a remote server by sending various buffer sizes to the target application. The script takes three arguments: an IP address, a port number, and an optional increment flag. 

It runs the target program multiple times, each time with a different buffer size, in an attempt to crash the target
program. The IP address and port number must be provided when running the script, and the increment flag can be optionally specified to set the step size for the buffer size increases. By default, the increment value is set to 100 bytes. 

The purpose of this script is to test the robustness of the target program by simulating various attack scenarios. It is intended for use in a controlled testing environment and should not be used to target production systems or networks without proper authorization.

Usage:

```
001_automatic_fuzzer.py [-h] [-i INCREMENT] ip port
001_automatic_fuzzer.py 127.0.0.1 1234
001_automatic_fuzzer.py 127.0.0.1 1234 -i 1000
```

Positional arguments:
  ip    					IP address of the target
  port					Port number of the target

Optional arguments:
  -h, --help                                                      					 show this help message and exit
  -i INCREMENT, --increment INCREMENT					Increment value to be used, default is 100
