#ifndef __SMARTA_H
#define __SMARTA_H

#include "ae.h"
#include "sds.h"
#include "list.h"
#include "xmpp.h"

typedef struct _Event {
    char *severity;
    char *trhead;
    char *subject;
    list *heads;
    char *body;
} Event;

typedef struct _Service {
    char *name;
    long period;
    char *command;
    long taskid;
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
