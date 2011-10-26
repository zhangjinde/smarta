#ifndef __SMARTA_H
#define __SMARTA_H

#include "adlist.h"
#include "xmpp.h"
#include "sds.h"
#include "ae.h"

typedef struct _Service {
    char *name;
    long period;
    char *command;
} Service;

typedef struct _Command {
    char *name;
    char *usage;
} Command;

typedef struct _Smarta {
    char *name;
    char *server;
    char *apikey;
    int isslave;
    char *pidfile;
    int daemonize;
    char *masterhost;
    char *masterauth;
    int masterport;
    list *services;
    aeEventLoop *el;
    char *logfile;
    int verbosity;
    XmppStream *stream;
} Smarta;

#endif
