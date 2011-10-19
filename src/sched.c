
#include <stdio.h>
#include <stdlib.h>

#include "xmpp.h"
#include "common.h"
#include "sched.h"
#include "adlist.h"
#include "smarta.h"
#include "common.h"

extern smarta_t smarta;

static int check_service(xmpp_conn_t * const conn, void * const userdata);

void sched_services(xmpp_ctx_t *ctx, xmpp_conn_t *conn) {
    service_t *service;
    listNode *node;
    listIter *iter = listGetIterator(smarta.services, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        service = (service_t *)node->value;
        printf("sched service: %s\n", service->name);
        //FUCK: could only add one handler!!!
        handler_add_timed(conn, check_service, service->period*1000, service);
    }
}

int check_service(xmpp_conn_t *conn, void *userdata) {
    service_t *service = (service_t *)userdata;
    printf("check service: %s\n", service->name);
    return 1;
}


