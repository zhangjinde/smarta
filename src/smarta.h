#ifndef __SMARTA_H
#define __SMARTA_H

#include "ae.h"
#include "sds.h"
#include "list.h"
#include "hash.h"
#include "xmpp.h"

typedef struct _Service {
    char *name;
    long period;
    char *command;
    long taskid;
} Service;

typedef struct _Command {
    char *usage;
    char *shell;
} Command;

typedef struct _Smarta {
    char *name;
    char *server;
    char *apikey;
    int isslave;
    char *pidfile;
    int collectd;
    int collectd_port;
    int daemonize;
    int heartbeat;
    char *masterhost;
    char *masterauth;
    list *services;
    list *commands;
    char *cmdusage;
    list *slaves;
    aeEventLoop *el;
    char *logfile;
    int verbosity;
    XmppStream *stream;
    char neterr[1024];

    //events cache
    Hash *events;
    
    
    //master/slave
    int masterfd;
    int masterport;
    char *slaveip;
    int slaveport;
    //stats
    int stat_slaves;
} Smarta;

#endif
