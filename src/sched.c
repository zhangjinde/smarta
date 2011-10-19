
#include <stdio.h>
#include <stdlib.h>
#include <strophe.h>
#include "common.h"
#include "sched.h"

static int sched_service(xmpp_conn_t * const conn, void * const userdata);

void sched_services(xmpp_ctx_t *ctx, xmpp_conn_t *conn) {
    
    handler_add_timed(conn, sched_service, 30*1000, ctx);

}

sched_service(xmpp_conn_t * const conn, void * const userdata) {
    
    printf("sched service....\n");

}


