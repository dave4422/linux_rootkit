/*
 * portknocking.h
 *
 *  Created on: 02.12.2018
 *      Author: Benjamin
 */

#ifndef PORTKNOCKING_H_
#define PORTKNOCKING_H_
#include <linux/types.h>

/* struct for saving information about sender and port */
struct sender_node {
	int protocol;
	int knocking_counter;

	u8 ipv4_addr[4];
	u8 ipv6_addr[16];
};

#endif /* PORTKNOCKING_H_ */
