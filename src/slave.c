/*
**
** slave.c - smarta master/slave
**
** Copyright (c) 2011 nodebus.com
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License version 2 as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
**
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>

#include "ae.h"
#include "anet.h"
#include "list.h"
#include "logger.h"
#include "slave.h"
#include "smarta.h"
#include "zmalloc.h"

extern Smarta smarta;

static Slave *slave_create(int slave_fd, int xmpp_fd);

static void read_from_slave(aeEventLoop *el, int fd, void *privdata, int mask); 

static void read_from_xmpp(aeEventLoop *el, int fd, void *privdata, int mask); 

static void slave_release(Slave *slave);

void slave_accept_handler(aeEventLoop *el, int listenfd, void *privdata, int mask)
{
    char ip[128];
    int port, fd, xmppfd;
    fd = anetTcpAccept(smarta.neterr, listenfd, ip, &port);
    if (fd == AE_ERR) {
        logger_warning("SLAVE","Accepting client connection: %s", smarta.neterr);
        return;
    }
    logger_info("SLAVE", "slave %s:%d is connected.", ip, port);

    if(smarta.slaveip) {//FIXME: both master and slave
        xmppfd = anetTcpConnect(smarta.neterr, smarta.slaveip, smarta.slaveport);
    } else {
        xmppfd = anetTcpConnect(smarta.neterr, smarta.server, 5222);
    }
    if(xmppfd < 0) {
        logger_warning("SLAVE", "failed to connect %s:%d,", smarta.server, 5222);
        close(fd);
        return;
    }
    logger_debug("SLAVE", "connect xmpp server for slave %s:%d", ip, port);
    Slave *slave = slave_create(fd, xmppfd);
    if(slave) {
        slave->port = port;
        slave->ip = zstrdup(ip);
        listAddNodeTail(smarta.slaves, slave);
    }
}

static Slave *slave_create(int fd, int xmppfd) {
    Slave *slave = zmalloc(sizeof(Slave));
    slave->fd = fd;
    slave->xmppfd = xmppfd;
    
    anetNonBlock(NULL,fd);
    anetTcpNoDelay(NULL,fd);
    
    if (aeCreateFileEvent(smarta.el, fd, AE_READABLE,
        read_from_slave, slave) == AE_ERR) {
        close(fd);
        close(xmppfd);
        zfree(slave);
        return NULL;
    }
    if (aeCreateFileEvent(smarta.el, xmppfd, AE_READABLE,
        read_from_xmpp, slave) == AE_ERR) {
        close(fd);
        close(xmppfd);
        zfree(slave);
        return NULL;
    }
    return slave;
}

static void read_from_slave(aeEventLoop *el, int fd, void *privdata, int mask) 
{ 
    int nread;
    char buf[4096] = {0};
    Slave *slave = (Slave *)privdata;
    nread = read(fd, buf, 4095);
    if(nread <= 0) {
        if(errno == EAGAIN) return;
        logger_info("SLAVE", "slave %s:%d is disconnected.", slave->ip, slave->port);
        slave_release(slave);
        return;
    }
    logger_debug("SLAVE", "%d data from slave: %s", nread, buf);
    anetWrite(slave->xmppfd, buf, nread);
}

static void read_from_xmpp(aeEventLoop *el, int fd, void *privdata, int mask) 
{ 
    int nread;
    char buf[4096] = {0};
    Slave *slave = (Slave *)privdata;
    nread = read(fd, buf, 4095);
    if(nread <= 0) {
        if(errno == EAGAIN) return;
        logger_debug("SLAVE", "xmpp server is disconnected.");
        slave_release(slave);
        return;
    }
    logger_debug("SLAVE", "%d data from xmpp server: %s", nread, buf);
    anetWrite(slave->fd, buf, nread);
}

static void slave_release(Slave *slave) 
{
    listNode *node;
    if(slave->xmppfd > 0) {
        aeDeleteFileEvent(smarta.el, slave->xmppfd, AE_READABLE);
        close(slave->xmppfd);
        slave->xmppfd = -1;
    }
    if(slave->fd > 0) {
        aeDeleteFileEvent(smarta.el, slave->fd, AE_READABLE);
        close(slave->fd);
        slave->fd = -1;
    }
    if(slave->ip) {
        zfree(slave->ip);
    }
    node = listSearchKey(smarta.slaves, slave);
    if(node) listDelNode(smarta.slaves, node);
    zfree(slave);
}

