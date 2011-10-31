
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "anet.h"
#include "xmpp.h"
#include "jid.h"
#include "sched.h"
#include "smarta.h"
#include "list.h"
#include "logger.h"
#include "zmalloc.h"

#define MAX_INPUT_BUFFER 4096

extern Smarta smarta;

static int check_service(struct aeEventLoop *el, long long id, void *clientdata);

static void sched_emit_event(XmppStream *stream, char *buf);

static int is_valid(char *buf);

void sched_run(aeEventLoop *el, list *services) {
    long taskid;
    int delay = 0;
    listNode *node;
    Service *service;
    signal(SIGCHLD, SIG_IGN);
    listIter *iter = listGetIterator(services, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        delay = (random() % 300) * 1000;
        service = (Service *)node->value;
        logger_debug("sched", "schedule service '%s' after %d seconds", 
            service->name, delay/1000);
        taskid = aeCreateTimeEvent(el, delay, check_service, service, NULL);
        service->taskid = taskid;
    }
    listReleaseIterator(iter);
}

int check_service(struct aeEventLoop *el, long long id, void *clientdata) {
    Service *service = (Service *)clientdata;
    pid_t pid = 0;
    pid = fork();
    if(pid == -1) {
        logger_error("SCHED", "fork error when check %s", service->name);
    } else if(pid == 0) { //subprocess
        int len;
        FILE *fp = NULL;
        char output[1024] = {0};
        sds result =sdsempty();
        sds raw_command = sdsnew("cd /opt/csmarta/plugins ; ./");
        Service *service = (Service *)clientdata;
        raw_command = sdscat(raw_command, service->command);
        logger_debug("SCHED", "check service: '%s'", service->name);
        logger_debug("SCHED", "command: '%s'", raw_command);
        fp = popen(raw_command, "r");
        if(!fp) {
            logger_error("failed to open %s", service->command);
            exit(0);
        }
        while(fgets(output, 1023, fp)) {
            result = sdscat(result, output);
        }
        if((len = sdslen(result)) > 0) {
            anetUdpSend("127.0.0.1", smarta.collectd, result, sdslen(result));
        }
        sdsfree(raw_command);
        sdsfree(result);
        pclose(fp);
        exit(0);
    } else {
        //FIXME: later
    }

    return service->period;
}

void sched_check_result(aeEventLoop *el, int fd, void *privdata, int mask) {
    int nread;
    char buf[1024] = {0};
    nread = read(fd, buf, 1023);
    XmppStream *stream = (XmppStream *)privdata;
    if(nread <= 0) {
        logger_debug("COLLECTD", "no data");
        return;
    }
    logger_debug("COLLECTD", "RECV: %s", buf);
    if(is_valid(buf) && stream->state == XMPP_STREAM_ESTABLISHED) {
        sched_emit_event((XmppStream *)privdata, buf);
    }
}

static void sched_emit_event(XmppStream *stream, char *buf) 
{
    listNode *node;
    char *jid, *domain;
    XmppStanza *message, *body, *text;
    listIter *iter = listGetIterator(stream->presences, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        jid = (char *)node->value;
        domain =xmpp_jid_domain(jid); 
        if(strcmp(domain, "nodehub.cn") == 0) {
            printf("send message to %s\n:%s", jid, buf);
            message = xmpp_stanza_newtag("message");
            xmpp_stanza_set_type(message, "chat");
            xmpp_stanza_set_attribute(message, "to", jid);

            body = xmpp_stanza_newtag("body");
            text = xmpp_stanza_new();
            xmpp_stanza_set_text(text, buf);
            xmpp_stanza_add_child(body, text);

            xmpp_stanza_add_child(message, body);

            xmpp_send_stanza(stream, message);
            xmpp_stanza_release(message);
        }
        zfree(domain);
    }
    listReleaseIterator(iter);
}

static int is_valid(char *buf) 
{
    if(strncmp(buf, "OK", 2) == 0) return 1;
    if(strncmp(buf, "WARNING", 7) == 0) return 1;
    if(strncmp(buf, "CRITICAL", 8) == 0) return 1;
    return 0;
}

