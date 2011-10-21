
#include <stdio.h>
#include <stdlib.h>

#include "xmpp.h"
#include "sched.h"
#include "adlist.h"
#include "smarta.h"

#define MAX_INPUT_BUFFER 4096

extern Smarta smarta;

static int check_service(XmppConn * const conn, void * const userdata);
static void send_message(XmppConn * conn, sds result);

void sched_services(XmppConn *conn) {
    Service *service;
    listNode *node;
    listIter *iter = listGetIterator(smarta.services, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        service = (Service *)node->value;
        printf("sched service: %s\n", service->name);
        //FUCK: could only add one handler!!! *60
        handler_add_timed(conn, check_service, service->period*60*1000, service);
    }
}

int check_service(XmppConn *conn, void *userdata) {
    FILE *fp = NULL;
	char output_buffer[MAX_INPUT_BUFFER] = "";
	sds raw_command = sdsnew("cd /opt/csmarta/plugins ; ./");
    sds result =sdsempty();
    Service *service = (Service *)userdata;
    printf("check service: %s\n", service->name);
    raw_command = sdscat(raw_command, service->command);
    fp = popen(raw_command, "r");
    while(fgets(output_buffer, sizeof(output_buffer) - 1, fp)) {
        result = sdscat(result, output_buffer);
    }
    pclose(fp);
    printf("check result:  %s\n", result);

    send_message(conn, result);
    sdsfree(result);
    return 1;
}

void send_message(XmppConn *conn, sds result) {
    XmppStanza *reply, *body, *text;
    
	reply = xmpp_stanza_new();
	xmpp_stanza_set_name(reply, "message");
	xmpp_stanza_set_type(reply, "chat");
	xmpp_stanza_set_attribute(reply, "to", "erylee@nodehub.cn");
	
	body = xmpp_stanza_new();
	xmpp_stanza_set_name(body, "body");
	
	text = xmpp_stanza_new();
	xmpp_stanza_set_text(text, result);
	xmpp_stanza_add_child(body, text);
	xmpp_stanza_add_child(reply, body);
	
	xmpp_send(conn, reply);
	xmpp_stanza_release(reply);
}
    
