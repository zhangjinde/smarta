
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>

#include "list.h"
#include "event.h"
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

static void sched_emit_event(XmppStream *stream, Event *event);

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
        sds raw_command = sdsnew("cd plugins ; ./");
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
        if((len = sdslen(result) && is_valid(result)) > 0) {
            sds data = sdscat(service->name, " ");
            data = sdscat(data, result);
            anetUdpSend("127.0.0.1", smarta.collectd, data, sdslen(data));
            sdsfree(data);
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

static int is_valid_event(Event *event) {

    if(!event) return 0;
    if(!event->status) return 0;
    if(!event->service) return 0;
    if(!event->subject) return 0;
    return 1;
}

void sched_check_result(aeEventLoop *el, int fd, void *privdata, int mask) {
    int nread;
    Event *event;
    char buf[1024] = {0};
    nread = read(fd, buf, 1023);
    XmppStream *stream = (XmppStream *)privdata;
    if(nread <= 0) {
        logger_debug("COLLECTD", "no data");
        return;
    }
    logger_debug("COLLECTD", "RECV: %s", buf);
    if(stream->state == XMPP_STREAM_ESTABLISHED) {
        event = event_parse(buf);
        if(is_valid_event(event)) {
            //Old event will be released by hash_add
            hash_add(smarta.events, event->service, event);
            sched_emit_event(stream, event);
        }
        //event_free(event);
    }
}

static char *event_to_string(Event *event) 
{
    sds s = sdsempty();
    s = sdscatlen(s, event->service, sdslen(event->service));
    s = sdscat(s, " ");
    s = sdscatlen(s, event->status, sdslen(event->status));
    s = sdscat(s, " - ");
    s = sdscatlen(s, event->subject, sdslen(event->subject));
    if(event->body) {
        s = sdscat(s, "\n\n");
        s = sdscatlen(s, event->body, sdslen(event->body));
    }
    return s;
}

static char *strcatnew(char *s1, char *s2) 
{
    int len1 = strlen(s1);
    int len2 = strlen(s2);
    char *key = zmalloc(len1 + len2 +1);
    memcpy(key, s1, len1);
    memcpy(key+len1, s2, len2); 
    *(key+len1+len2) = '\0'; 
    return key;
}

static int should_emit(XmppStream *stream, char *jid, Event *event) 
{
    int yes;
    char *key, *val, *status;
    key = strcatnew(jid, event->service); 
    val = zstrdup(event->status);
    if((status = hash_get(stream->events, key))) {
        if(strcmp(status, event->status)) {
            yes = 1;
        } else {
            yes = 0;
        }
    } else {
        if(strcmp(val, "OK"))  { 
            yes = 1; 
        } else {
            yes = 0;
        }
    }
    hash_add(stream->events, key, val);
    return yes;
}

static void sched_emit_event(XmppStream *stream, Event *event) 
{
    char *buf;
    listNode *node;
    char *jid, *domain;
    XmppStanza *message, *body, *text;
    listIter *iter = listGetIterator(stream->presences, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        jid = (char *)node->value;
        domain =xmpp_jid_domain(jid); 
        if(!strcmp(domain, "nodehub.cn") 
            && should_emit(stream, jid, event)) {
            buf = event_to_string(event);
            printf("send message to %s: %s", jid, buf); 
            message = xmpp_stanza_tag("message");
            xmpp_stanza_set_type(message, "chat");
            xmpp_stanza_set_attribute(message, "to", jid);

            body = xmpp_stanza_tag("body");
            text = xmpp_stanza_cdata(buf);
            xmpp_stanza_add_child(body, text);

            xmpp_stanza_add_child(message, body);

            xmpp_send_stanza(stream, message);
            xmpp_stanza_release(message);
            sdsfree(buf);
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

