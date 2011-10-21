#ifndef _SMARTA_H_
#define _SMARTA_H_

#include "adlist.h"
#include "sds.h"

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
} Smarta;

#endif
