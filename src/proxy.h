#ifndef __PROXY_H
#define __PROXY_H

void proxy_accept_handler(aeEventLoop *el, int listenfd, void *privdata, int mask);

#endif
