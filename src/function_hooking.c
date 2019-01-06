#include "function_hooking.h"
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/linkage.h>
#include <linux/slab.h>
//#include <linux/uaccsess.h>

/* Dis-/Enable debugging for this module */
#define DEBUG_MODULE	0

#if DEBUG_MODULE == 0
#undef DEBUG(f_, ...)
#define DEBUG(f_, ...)
#endif

/**** Prototypes ***/
static int resolve_hook_address (function_hook_t *hook);
static void delete_data_in_list(void);
void notrace callback_ftrace(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs);
static void enable_sys_hook(function_hook_t *hook);
static void remove_sys_hook(function_hook_t *hook);
void install_ftrace_hook(function_hook_t *hook);
static void fh_remove_hook (function_hook_t *hook);
static int fh_install_hook (function_hook_t *hook);

/************* Local data ********/
/* Syscall table */
static void **syscall_table_pu64;
list_t *function_hooks = NULL;

function_hook_t *add_function_hook_to_list(char *f_name,
		void *function, void *p_to_func_var){
	function_hook_t *new_hook;
	if(function_hooks == NULL){
		function_hooks = list_init();
	}
	new_hook = (function_hook_t *)kmalloc(sizeof(function_hook_t), GFP_KERNEL);
	memset(new_hook, 0, sizeof(function_hook_t));
	atomic_set(&new_hook->usage_count, 0);
	new_hook->name = (char *)kmalloc(strlen(f_name)+1, GFP_KERNEL);
	sprintf(new_hook->name, "%s", f_name);
	new_hook->hook_function = function;
	new_hook->original_function = p_to_func_var;
	new_hook->address = 0;
	new_hook->hook_type = HOOK_TYPE_FTRACE;
	list_append(function_hooks, (void *)new_hook);
	return new_hook;
}

function_hook_t *add_syscall_to_hook(void *hook_function,
		unsigned int offset){
	function_hook_t *tmp;
	if(function_hooks == NULL){
		function_hooks = list_init();
	}
	tmp = (function_hook_t *)kmalloc(sizeof(function_hook_t), GFP_KERNEL);
	memset(tmp, 0, sizeof(function_hook_t));
	atomic_set(&tmp->usage_count, 0);
	tmp->name = NULL;
	tmp->original_function = NULL;
	tmp->hook_function = hook_function;
	tmp->offset = offset;
	tmp->hook_type = HOOK_TYPE_SYSCALL;
	list_append(function_hooks, (void *)tmp);
	return tmp;
}


/*
 * Iterates through hook list and enables all hooks.
 */
void hook_functions_in_list(void){
	struct list_elem *tmp;
	int count;
	function_hook_t *hook_p;

	syscall_table_pu64 = (void **)kallsyms_lookup_name("sys_call_table");
	if(function_hooks == NULL){
		return;
	}

	count = 0;
	tmp = list_give_nth_elem(function_hooks, count);
	while(tmp != NULL){
		hook_p = (function_hook_t *)tmp->data;
		if(hook_p->hook_type == HOOK_TYPE_FTRACE){
			fh_install_hook(hook_p);
		}
		else if(hook_p->hook_type == HOOK_TYPE_SYSCALL){
			/* remove write protection */
			write_cr0 (read_cr0 () & (~ 0x10000));
			enable_sys_hook(hook_p);
			/* enable write protection */
			write_cr0 (read_cr0 () | 0x10000);
		}
		count++;
		tmp = list_give_nth_elem(function_hooks, count);
	}

}

/*
 * Iterates through hook list and disables all hooks and cleans the memory.
 */
void cleanup_function_hooking(void){
	struct list_elem *tmp;
	int count;
	function_hook_t *hook_p;
	int fault_count = 0;
	if(function_hooks == NULL){
		return;
	}
	/* remove write protection */
	write_cr0 (read_cr0 () & (~ 0x10000));
	count = 0;
	tmp = list_give_nth_elem(function_hooks, count);
	while(tmp != NULL){
		hook_p = (function_hook_t *)tmp->data;
		if(hook_p->hook_type == HOOK_TYPE_FTRACE){
			fh_remove_hook(hook_p);
		}
		else if(hook_p->hook_type == HOOK_TYPE_SYSCALL){
			remove_sys_hook(hook_p);
		}
		fault_count = 0;
		while(atomic_read(&hook_p->usage_count) > 0){
			// wait for all calls on the function to be completed
			fault_count++;
			if(fault_count == 100000){
				DEBUG(KERN_INFO "not exiting func, %d use it LOL", atomic_read(&hook_p->usage_count));
			}
		}
		count++;
		tmp = list_give_nth_elem(function_hooks, count);
	}
	/* enable write protection */
	write_cr0 (read_cr0 () | 0x10000);
	delete_data_in_list();
	list_cleanup(function_hooks);
}

void inc_use_count(function_hook_t *hook){
	atomic_inc(&hook->usage_count);
}

void dec_use_count(function_hook_t *hook){
	atomic_dec(&hook->usage_count);
}


/********************* PRIVATE FUNCTIONS ***************/
static void enable_sys_hook(function_hook_t *hook){
	hook->original_function = (void *)syscall_table_pu64[hook->offset];
	syscall_table_pu64[hook->offset] = hook->hook_function;
}

static void remove_sys_hook(function_hook_t *hook){
	syscall_table_pu64[hook->offset] = hook->original_function;
}

static int fh_install_hook (function_hook_t *hook){

	int err;

	err = resolve_hook_address(hook);
	if (err) {
		return err;
	}
	/*
	 * use recursion safe, so that recursion can be used. Use save regs option and IP modifdy
	 * to get the saved registers and change the new called function to the function we hook.
	 */
	hook->ops.func = callback_ftrace;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_RECURSION_SAFE;

	/* Solves a problem in the kernel I believe with Null pointer dereference */
	hook->ops.func_hash = NULL;
	hook->ops.local_hash.notrace_hash = NULL;
	hook->ops.local_hash.filter_hash = NULL;

	hook->ops.old_hash.notrace_hash = NULL;
	hook->ops.old_hash.filter_hash = NULL;


	DEBUG("set filter ip, address is %ul", hook->address);
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		DEBUG("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	DEBUG("reached registering ftrace");
	err = register_ftrace_function(&hook->ops);
	if (err) {
		DEBUG("register_ftrace_function() failed: %d\n", err);

		/* Unregister ftrace if registering did not work. */
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);

		return err;
	}

	return 0;
}

static void fh_remove_hook (function_hook_t *hook){
	int err;

	err = (int)unregister_ftrace_function(&hook->ops);
	if(err){
		DEBUG("unregister_ftrace_function() failed: %d\n", err);
	}

	err = (int)ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		DEBUG( "ftrace_set_filter_ip() failed: %d\n", err);
	}
}



static void delete_data_in_list(void){
	struct list_elem *tmp;
	function_hook_t *hook_p;
	int count;
	count = 0;
	tmp = list_give_nth_elem(function_hooks, count);
	while(tmp != NULL){
		hook_p = (function_hook_t *)tmp->data;
		if(hook_p->name != NULL){
			kfree(hook_p->name);
		}
		kfree(hook_p);
		count++;
		tmp = list_give_nth_elem(function_hooks, count);
	}
}

/********** Private functions ****************/

void notrace callback_ftrace(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs){
	function_hook_t *hook;
	/* get the hole structure in which ops pointer is located */
	hook = container_of(ops, function_hook_t, ops);

	/* recursion protection done by offset in resolve hook address */
//	regs->ip = (unsigned long)hook->original_function;

	/* for alternative recursion protection */
	DEBUG("called func is %ul\n", (unsigned long)hook->hook_function);
	if(!within_module(parent_ip, THIS_MODULE)){
		regs->ip = (unsigned long)hook->hook_function;
	}
}


static int resolve_hook_address (function_hook_t *hook){

	DEBUG("hook function %s.\n", hook->name);
	hook->address = kallsyms_lookup_name((const char *)hook->name);
	DEBUG("success with %s.\n", hook->name);
	if (hook->address == NULL || hook->address == 0) {
		DEBUG("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}
	/* Save the pointer to the original function plus the bytes used by ftrace */
//	*((unsigned long *)hook->original_function) = hook->address + MCOUNT_INSN_SIZE;

	/* for alternative recursion protection */
	*((unsigned long *)hook->original_function) = hook->address;


	DEBUG("resolved address succesfully");
	DEBUG("the hooking func is %ul\n", hook->hook_function);
	return 0;
}
