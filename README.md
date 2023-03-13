# Hack-the-Stack
This repository contains a collection of Python scripts designed to assess and exploit programs that are susceptible to buffer overflow attacks.

### 1. Crash Fuzzer

This is a Python script for fuzz testing a remote server by sending various buffer sizes to the target application. The script takes three arguments: an IP address, a port number, and an optional increment flag. 

It runs the target program multiple times, each time with a different buffer size, in an attempt to crash the target
program. The IP address and port number must be provided when running the script, and the increment flag can be optionally specified to set the step size for the buffer size increases. By default, the increment value is set to 100 bytes. 

The purpose of this script is to test the robustness of the target program by simulating various attack scenarios. It is intended for use in a controlled testing environment and should not be used to target production systems or networks without proper authorization.

Usage:

```
001_crash_fuzzer.py <ip> <port> [-i INCREMENT]
001_crash_fuzzer.py 127.0.0.1 1234
001_crash_fuzzer.py 127.0.0.1 1234 -i 1000
```

> Positional arguments:
>   ip - IP address of the target
>   port - Port number of the target
>
> Optional arguments:
>   -i/--increment INCREMENT - Increment value to be used, default is 100



### 2. Controlling the EIP

This is a Python script for controlling the eip of a process in a remote server by filling the target application's buffer with a cyclic pattern. 

The script takes three arguments: an IP address, a port number, and an overflow threshold. It takes advantage of the metasploit framework exploit /patter_create.rb and /pattern_offset.rb. 

Itis intended for use in a controlled testing environment and should not be used to target production systems or networks without proper authorization. 

**NOTE: Edit the script with the metasploit exploit location in your environment if you are getting an error. It assumes both exploits are located in the following directory "/usr/share/metasploit-framework/tools/exploit/".**

Usage:

```
002_eip_offset.py <ip> <port> <overflow_threshold>
002_eip_offset.py 127.0.0.1 1234 50000
```

> Positional arguments:
>   ip - IP address of the target
>   port - Port number of the target
>   overflow_threshold  Payload size which is able to crash the target application



### Finding Bad Characters
