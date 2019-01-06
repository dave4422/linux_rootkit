# Linux rootkit
This software was developed by students for the course Rootkit programming at Technical University of Munich (TUM)
in winter 2018/2019. It may be used for academic purposes only. This is only a screenshot from January 3rd 2019 and
not the development repository.

## Motivation
A rootkit is software that allows an attacker to maintain root access. 

## Features
* Process Hiding and Hiding of Process hierarchies 
Hide processes from the user in such a way that they are still scheduled.
* File Hiding
Hide files but they are still accessible to anyone who knows that they are there and exist.
* Module Hiding 
Hide LKMs.
* Socket Hiding 
Hide sockets from user space tools like `netstat` and `ss`.
* Packet Hiding 
Any TCP or UDP communication to and from specified ip address will be hidden from user space programms like `tcpdump, wireshark`.
* Port Knocking
* Privilege Escalation
Eescalate the privileges of a given process (via PID) to root.
* Network Key-logging 
Send data from `stdin` using the syslog protocol to a syslog-ng server.
* Command and Control programm
User space programm to controll functionality of rootkit over covert communication channel.
* (System Call Hooking) 

## Target Platform
The rootkit was developed for and tested with the [linux kernel 4.9.133](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/?h=v4.9.133).

## Installation
To compile the LKM rootkit run `make`.  
Compile the Command and Control with `gcc control_program.c -o cmd`.  

LKMs (Linux kernel modules) are pieces of code that can be loaded and unloaded into the kernel upon demand.
To load the rootkit into the kernel, run with root privileges:
```
insmod rootkit.ko
```
The rootkit automatically hides itself from lsmod.

To unload the rootkit, run with root privileges:
```
./cmd --unhide_rootkit
rmmod rootkit
```

## How to use?
With the command and control programm, commands can be send to the rootkit over an IOCTl channel.
```
$ ./cmd

Usage: ./cmd [OPTION]... [PARAM]...

Options:
	--hide_fd 				[PATH] 		Hide a file at path
	--unhide_fd 				[PATH] 		Unhide a file at path
	
	--hide_socket_tcp 			[PORT]		Hide tcp socket with port
	--unhide_socket_tcp 			[PORT]		Unhide tcp socket with port
	
	--hide_ps 				[PID]		Hide process with pid
	--unhide_ps 				[PID]		Unhide process with pid	
	
	--hide_child_pid					Enable child process hiding
	--unhide_child_pid					Disbale child process hiding
	
	--hide_mod 				[NAME]		Hide LKM by name
	--unhide_mod 				[NAME]		Unhide LKM by name
		
	--hide_package_v4 			[IPV4]		Hide IPV4 packages from ip address
	--hide_package_v4 			[IPV4]		Unhide IPV4 packages from ip address
	
	--hide_package_v6 			[IPV6]		Hide IPV6 packages from ip address
	--hide_package_v6 			[IPV6]		Unhide IPV6 packages from ip address
	
	--port_knocking 			[PORT]		Enable port knocking at port
	--disable_port_knocking 		[PORT]		Disable port knocking at port
	
	--privilege_pid 			[PID]		Privilege process with pid
	
	--log_on 						Enable keylogging
	--log_off 						Disable keylogging

```

## Technical details about the implementation
Please read the commentary in the code.

## Credits
To our supervisors at TUM. Thank you!

## Authors
Benjamin Zanger and David Mildenberger
