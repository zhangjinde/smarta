#ifndef __SLAVE_H
#define __SLAVE_H

typedef struct _Slave {
    char *ip;
    int port;
    int fd;
    int xmppfd;
} Slave;

void slave_accept_handler(aeEventLoop *el, int fd, void *privdata, int mask);

#endif

