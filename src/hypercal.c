#include <linux/moduleloader.h>
#include <linux/unistd.h>
#include <linux/reboot.h>
#include <asm/kvm_para.h>



static int __init init_mod(void)
{
	char buffer[100];
	kvm_hypercall1(999,buffer);
	printk(KERN_INFO"%s\n", buffer);
	return 0;
}

static void __exit  exit_mod(void)
{
}

module_init(init_mod);
module_exit(exit_mod);

MODULE_LICENSE("GPL"); 				/* Declare it as GPL License */
MODULE_AUTHOR("David und Benjamin");		/* Declare the Author        */
MODULE_DESCRIPTION(""); /* Short description         */
