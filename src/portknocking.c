/*
 * portknocking.c
 *
 *  Created on: 02.12.2018
 *      Author: Benjamin
 */


#include "portknocking.h"
#include "hook.h"
#include "list.h"
#include <linux/types.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include <net/netfilter/ipv6/nf_reject.h>

#include <net/tcp.h>

/* Dis-/Enable debugging for this module */
#define DEBUG_MODULE	1

#if DEBUG_MODULE == 0
#undef DEBUG(f_, ...)
#define DEBUG(f_, ...)
#endif


/* Length of ipv4 and ipv6 in bytes */
#define IPV4_LENGTH		4
#define IPV6_LENGTH     16

#define DENY_SENDER		1
#define ACCEPT_SENDER	0

/* global netfilter hook */
struct nf_hook_ops netf_hook;

/* list of hidden local ports */
list_t *ports;
list_t *senders;
list_t *knocking_ports; /* not used yet */

static int knocking_amount = 0;

/*********** PROTOTYPES *******************/
int cmp_ipv4_addr(void *ip_addr, void *sender);
int cmp_ipv6_addr(void *ip_addr, void *sender);

/*
 * Inserts a new sender into the sender list.
 */
struct list_elem *insert_sender(u8 *ip_addr, int protocol)
{
	struct sender_node *sender = kmalloc(sizeof(struct sender_node),GFP_KERNEL);

	sender->protocol = protocol;
	sender->knocking_counter = 0;

	if(protocol == htons(ETH_P_IP)) { /* if protocol 0x800, for ipv4 */
		memcpy(sender->ipv4_addr, ip_addr, IPV4_LENGTH);
		DEBUG("A new sender got inserted with IPv4\n");
	}else if(protocol == htons(ETH_P_IPV6)) { /* else for ipv6 */
		memcpy(sender->ipv6_addr, ip_addr, IPV6_LENGTH);
		DEBUG("A new sender got inserted with IPv6\n");
	}else{
		DEBUG("Error, protocol not known!\n");
	}

	return list_append(senders, (void *)sender);
}

/*
 * Compare function for list to find integer in list.
 */
int cmp_integers(void *v1, void *v2){
	int *i1, *i2;
	i1 = v1;
	i2 = v2;
	if(*i1 == *i2){
		return 0;
	}
	return -1;
}

/*
 * returns true if port found in list
 */
int find_port(int port)
{
	return list_find(ports, (void *)&port, cmp_integers) != NULL;
}

/*
 * Insert a new knocking port into the list.
 */
void insert_as_knocking_port(int port){
	int *new_port;
	new_port = kmalloc(sizeof(int), GFP_KERNEL);
	*new_port = port;
	list_append(knocking_ports, new_port);
	knocking_amount++;
}

int is_knock_port(int port)
{
	return list_find(knocking_ports, (void *)&port, cmp_integers) != NULL;
}

/*
 * Check if the sender has gained permission for tcp connection
 */
int check_sender_parameters(struct sender_node *sender, int protocol)
{
	if(sender != NULL) {

		/* check if the sender has permission */
		if(sender->protocol == protocol
				&& sender->knocking_counter == knocking_amount) {
			DEBUG("Sender in list, parameter correct, accpted.\n");
			return ACCEPT_SENDER; /* accept tcp request */
		}
	}

	DEBUG("Sender in list, but knocking not finished, access denied.\n");
	return DENY_SENDER; /* drop the tcp request */
}

int update_sender(u8 *addr, int protocol, int port)
{
	struct list_elem *node;
	struct sender_node *sender;


	if(protocol == htons(ETH_P_IP)) {
		DEBUG("Search for IPv4 %pI4.\n", addr);
		node = list_find(senders, (void *)addr, cmp_ipv4_addr);
	}
	else if(protocol == htons(ETH_P_IPV6)){
		DEBUG("Search for IPv6 %pI6.\n", addr);
		node = list_find(senders, (void *)addr, cmp_ipv6_addr);
	}
	else{
		/* Should not happen, deny if it does */
		return DENY_SENDER;
	}

	/*
	 * Check if Sender is in the list, if not make a new entry
	 */
	if(node == NULL) {
		DEBUG("Not found, new entry for the sender is created\n");
		node = insert_sender(addr, protocol);
	}

	sender = (struct sender_node *)node->data;


	/* Check if the sender goes through the right combination. If not delete him */
	struct list_elem *ele;
	ele = list_give_nth_elem(knocking_ports, sender->knocking_counter);
	int *k_port;
	k_port = ele->data;
	if(port == *k_port) {
		sender->knocking_counter++;
		DEBUG("Sender was updated, port %d was called.\n", port);
	}else{
		DEBUG("Wrong order, port %d was called and %d was expected, delete sender entry from list\n", port, *k_port);
		kfree(sender);
		list_remove(senders, node);
	}

	return DENY_SENDER;
}

/*
 * Compare function for the list to find sender for IPv4.
 */
int cmp_ipv4_addr(void *ip_addr, void *sender){
	void *ip;
	struct sender_node *send;
	send = sender;
	ip = (void *)send->ipv4_addr;
	return memcmp(ip_addr, ip, IPV4_LENGTH);
}

/*
 * Compare function for the list to find sender for IPv6.
 */
int cmp_ipv6_addr(void *ip_addr, void *sender){
	void *ip;
	struct sender_node *send;
	send = sender;
	ip = (void *)send->ipv6_addr;
	return memcmp(ip_addr, ip, IPV6_LENGTH);
}

/*
 * Checks if sender got permission. If sender not known, adds it
 * as new sender to the list.
 * Returns 1 if no permission, 0 if permission granted.
 */
int check_for_sender_permission(struct sk_buff *skb, int port)
{
	struct iphdr *header_ipv4;
	struct ipv6hdr *header_ipv6;

	/* get ip headers */
	header_ipv4 = ip_hdr(skb);
	header_ipv6 = ipv6_hdr(skb);

	DEBUG("Sender checking\n");

	/* Check if the port is hidden */
	if(find_port(port)) {
		if(skb->protocol == htons(ETH_P_IP) && header_ipv4 != NULL) {
			struct list_elem *node;
			struct sender_node *s_node;
			node = list_find(senders, (void *)&header_ipv4->saddr, cmp_ipv4_addr);
			if(node == NULL){
				/* Sender not found */
				DEBUG("Sender not found in list, access denied\n");
				return DENY_SENDER;
			}
			s_node = (struct sender_node *)node->data;
			return check_sender_parameters(s_node, htons(ETH_P_IP));
		}

		if(skb->protocol == htons(ETH_P_IPV6) && header_ipv6 != NULL) {
			struct list_elem *node;
			struct sender_node *s_node;
			node = list_find(senders, (void *)&header_ipv4->saddr, cmp_ipv6_addr);

			if(node == NULL){
				/* Sender not found */
				DEBUG("Sender not found in list, access denied\n");
				return DENY_SENDER;
			}
			s_node = (struct sender_node *)node->data;
			return check_sender_parameters(s_node, htons(ETH_P_IPV6));
		}
	}else {
		/*
		 * port is not hidden, check if it is a knocking port and add sender to list or increase counter
		 * for sender
		 */
		if(skb->protocol == htons(ETH_P_IP) && header_ipv4 != NULL) {
			return update_sender((u8 *)&header_ipv4->saddr,
					htons(ETH_P_IP), port);
		}

		if(skb->protocol == htons(ETH_P_IPV6) && header_ipv6 != NULL) {
			return update_sender(header_ipv6->saddr.s6_addr,
					htons(ETH_P_IPV6), port);
		}
	}

	return DENY_SENDER;
}

/*
 * netf hook function.
 */
unsigned int knock_port(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct iphdr *header_ipv4;
	struct ipv6hdr *header_ipv6;
	struct tcphdr *header_tcp;

	header_ipv4 = ip_hdr(skb);
	header_ipv6 = ipv6_hdr(skb);

	//	DEBUG("reached here\n");

	/* Check if there are ports which should be hided */
	if(list_is_empty(ports)){
		return NF_ACCEPT;
	}


	/* Accept packets which are not TCP for IPv4 */
	if(skb->protocol == htons(ETH_P_IP)) {
		if(header_ipv4->protocol != IPPROTO_TCP) {
			return NF_ACCEPT;
		}
	}


	/* Accept packets which are not TCP for IPv6 */
	if(skb->protocol == htons(ETH_P_IPV6)) {
		if(header_ipv6->nexthdr != IPPROTO_TCP) {
			return NF_ACCEPT;
		}
	}

	/* get tcp header */
	header_tcp = tcp_hdr(skb);


	/* accept if these ports are not hidden or knocking ports */
	if(!(is_knock_port(ntohs(header_tcp->dest))|| find_port(ntohs(header_tcp->dest)))){
		return NF_ACCEPT;
	}

	DEBUG("sender will check message.\n");

	/* Check about the sender permission */
	if(check_for_sender_permission(skb, ntohs(header_tcp->dest))) {
		DEBUG("permission denied.\n");
		/* permission not granted, response with TCP_RST */
		if(skb->protocol == htons(ETH_P_IP)) {
			nf_send_reset(state->net, skb, state->hook);
		}else if(skb->protocol == htons(ETH_P_IPV6)) {
			nf_send_reset6(state->net, skb, state->hook);
		}

		return NF_DROP;
	}

	DEBUG("permission granted\n");

	/* Otherwise permission granted */

	return NF_ACCEPT;
}


/*
 * Unhide a port which is hided
 */
void port_unhide(int port)
{
	struct list_elem *node = list_find(ports, (void *)&port,cmp_integers);

	if(node != NULL) {
		list_remove(ports, node);
	}

}

/*
 * Hide a new Port
 */
void port_hide(int port)
{
	int *new_port = kmalloc(sizeof(int), GFP_KERNEL);

	if(list_find(ports, (void *)&port, cmp_integers) != NULL) {
		return;
	}

	DEBUG("Port %d to hide is inserted", port);
	*new_port = port;
	list_append(ports, (void *)new_port);
}


void initialize_port_knocking(void)
{

	ports = list_init();
	senders = list_init();
	knocking_ports = list_init();

	insert_as_knocking_port(1500);
	insert_as_knocking_port(2000);
	insert_as_knocking_port(2500);

	netf_hook.hook = knock_port;
	/* make this hook get triggered at an incoming package */
	netf_hook.hooknum = NF_INET_LOCAL_IN;
	netf_hook.pf = PF_INET;
	netf_hook.priority = NF_IP_PRI_FIRST;

	int ret;
	/* init net from net_namespace */
	ret = nf_register_net_hook(&init_net, &netf_hook);

	if(ret < 0){
		DEBUG("oops, your portkncking hook did not register\n");
	}
	else{
		DEBUG("Registering for port knocking was succesfull\n");
	}

}

void remove_port_knocking(void)
{
	list_cleanup_with_data_clean(ports);
	list_cleanup_with_data_clean(senders);
	list_cleanup_with_data_clean(knocking_ports);
	nf_unregister_net_hook(&init_net, &netf_hook);
}
