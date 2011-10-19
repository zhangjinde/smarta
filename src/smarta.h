#ifndef _SMARTA_H_
#define _SMARTA_H_

#include "adlist.h"
#include "sds.h"

typedef struct _service_t {
    char *name;
    long period;
    char *command;
} service_t;

typedef struct _smarta_t {
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
} smarta_t;

typedef struct _command_t {
    char *name;
    char *usage;
} command_t;

#endif
