#ifndef HIDE_SOCKET_H
#define HIDE_SOCKET_H

typedef enum protocol{
	p_none = 0,
	p_tcp = 1,
	p_tcp6 = 2,
	p_udp = 3,
	p_udp6 = 4,
	p_all = 5,
}protocol_e;

#endif
