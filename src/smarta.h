#ifndef __SMARTA_H
#define __SMARTA_H

#include "ae.h"
#include "sds.h"
#include "list.h"
#include "hash.h"
#include "xmpp.h"

typedef struct _Sensor{
    char *name;
    long period;
    char *command;
    long taskid;
} Sensor;

typedef struct _Command {
    char *usage;
    char *shell;
    #ifdef __CYGWIN__
    void *fun; 
	#endif
} Command;

typedef struct _Emitted {
    char *jid;
    char *sensor;
    int status;
} Emitted;

typedef struct _Smarta {
    char *name;
    char *server;
    char *apikey;
    int isslave;
    char *pidfile;
    int collectd;
    int collectd_port;
    int daemonize;
    long long heartbeat;
    long long heartbeat_timeout;
    int shutdown_asap;
    char *masterhost;
    char *masterauth;
    list *sensors;
    list *commands;
    char *cmdusage;
    list *slaves;
    aeEventLoop *el;
    char *logfile;
    int verbosity;
    XmppStream *stream;
    char neterr[1024];
    //global buddies
    list *buddies;

    //events cache
    Hash *events;
    
    //emitted
    list *emitted;
    
    //master/slave
    int masterfd;
    int masterport;
    char *slaveip;
    int slaveport;
    //proxy
    int proxyfd;
    int proxyport;
    //stats
    int stat_slaves;
	#ifdef __CYGWIN__
	list *plugins;
    #endif
} Smarta;

#endif
