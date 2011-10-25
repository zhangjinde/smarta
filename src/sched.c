
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "xmpp.h"
#include "sched.h"
#include "adlist.h"
#include "smarta.h"

#define MAX_INPUT_BUFFER 4096

extern Smarta smarta;

static int check_service(struct aeEventLoop *el, long long id, void *clientdata);

static void send_message(XmppStream *stream , sds result);

void sched_run() {
    Service *service;
    listNode *node;
    listIter *iter = listGetIterator(smarta.services, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        service = (Service *)node->value;
        printf("sched service: %s\n", service->name);
        aeCreateTimeEvent(smarta.el, service->period*60*1000, 
            check_service, service, NULL);
    }
}

int check_service(struct aeEventLoop *el, long long id, void *clientdata) {
    pid_t pid = 0;
    pid = fork();
    if(pid == -1) {
        return -1;
    } else if(pid == 0) { //subprocess
        FILE *fp = NULL;
        char output_buffer[MAX_INPUT_BUFFER] = "";
        sds raw_command = sdsnew("cd /opt/csmarta/plugins ; ./");
        sds result =sdsempty();
        Service *service = (Service *)clientdata;
        printf("check service: %s\n", service->name);
        raw_command = sdscat(raw_command, service->command);
        fp = popen(raw_command, "r");
        while(fgets(output_buffer, sizeof(output_buffer) - 1, fp)) {
            result = sdscat(result, output_buffer);
        }
        pclose(fp);
        printf("check result:  %s\n", result);
        //send_message(conn, result);
        sdsfree(result);
    } else {//current
        //FIXME: later
    }

    return 1;
}

void send_message(XmppStream *stream, sds result) {
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
	
	xmpp_send(stream, reply);
	xmpp_stanza_release(reply);
}
 
