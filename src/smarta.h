#ifndef _SMARTA_H_
#define _SMARTA_H_

typedef struct service_t {
    char *name;
    long period;
    char *cmd;
    struct service_t *next;
} service;

#endif
