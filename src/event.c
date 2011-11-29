#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "sds.h"
#include "list.h"
#include "event.h"
#include "zmalloc.h"

static char *parse_sensor_line(Event *event, char *buf);

static char *parse_status_line(Event *event, char *buf);

static void parse_status(Event *event, char *start, char *end);

static char *parse_head_lines(Event *event, char *buf);

static void parse_body(Event *event, char *buf);

static void strfree(void *s);

Event *event_new() 
{
    Event *event = zmalloc(sizeof(Event));
    event->status = -1;
    event->sensor = NULL;
    event->title = NULL;
    event->heads = listCreate();
    listSetFreeMethod(event->heads, strfree);
    event->body = sdsempty();
    return event;
}

char *event_status(Event *event) 
{
    if(event->status == 2) {
        return "CRITICAL";
    }
    if(event->status == 1) {
        return "WARNING";
    }
    if(event->status == 0) {
        return "OK";
    }
    return "UNKNOWN";
}

int event_has_heads(Event *event) 
{
    return listLength(event->heads);       
}

sds event_heads_to_string(Event *event)
{
    sds buf = sdsempty();
    listNode *node;
    listIter *iter = listGetIterator(event->heads, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        buf = sdscat(buf, (char *)node->value);   
    }
    listReleaseIterator(iter);
    return buf;
}

sds event_metrics_to_string(Event *event)
{
    sds buf = sdsempty();
    listNode *node;
    listIter *iter = listGetIterator(event->heads, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        //start with
        if(strncmp(node->value, "metric:", 7) == 0) {
            buf = sdscat(buf, (char *)(node->value + 7));   
        }
    }
    listReleaseIterator(iter);
    return buf;
}

void event_free(Event *event) 
{
    if(!event)  return;
    if(event->sensor) {
        sdsfree(event->sensor);
    }
    if(event->title) {
        sdsfree(event->title);
    }
    if(event->body) {
        sdsfree(event->body);
    }
    if(event->heads) {
        listRelease(event->heads); 
    }
    zfree(event);
}

Event *event_feed(char *buf) 
{
    if(strncmp(buf, "sensor/1.0", 10)) {//FIXME: check version later.
        return NULL;
    }
    Event *event = event_new();
    buf = parse_sensor_line(event, buf+10);
    if(buf && *buf) {
        buf = parse_status_line(event, buf);
    }
    if(buf && *buf) {
        buf = parse_head_lines(event, buf);
    }
    if(buf && *buf) {
        parse_body(event, buf);
    }
    return event;
    
}

static char *parse_sensor_line(Event *event, char *buf)
{        
    char *p = buf;
    char *sp = NULL;
    char *eol = NULL; 
    while(p && *p) {
        if(*p == ' ') {
            if(!sp) sp = p;
        } else if(*p == '\n') {
            eol = p++;
            break;
        } 
        p++;
    }
    if(eol) event->sensor = sdsnewlen(sp+1, eol-sp-1);
    return p;
}

static char *parse_status_line(Event *event, char *buf)
{        
    char *p = buf;
    char *eol = NULL;
    char *sep = NULL;
    while(p && *p) {
        if(*p == '-') {
            if(!sep) sep = p;
        }else if(*p == '\n') {
            eol = p++;
            break;
        } 
        p++;
    }
    if(sep) parse_status(event, buf, sep-1);
    if(eol) event->title = sdsnewlen(sep+2, eol-sep-2);
    return p;
}

static void parse_status(Event *event, char *start, char *end)
{
    if(strncmp("OK", start, end - start) == 0) {
        event->status = OK; 
    } else if(strncmp("WARNING", start, end - start) == 0) {
        event->status = WARNING;
    } else if(strncmp("CRITICAL", start, end - start) == 0) {
        event->status = CRITICAL;
    } else { //if(strncmp("UNKNOWN", start, end - start) == 0) {
        event->status = UNKNOWN;
    }
}

static char *parse_head_lines(Event *event, char *buf)
{
    sds line;
    char *p = buf;
    int in_eof = 0;
    if(*buf == '\n') {//no heads
        return ++buf;
    }
    
    while(p && *p) {
        if(*p == '\n') {
            if(in_eof) return ++p;
            line = sdsnewlen(buf, (p-buf)+1); //contain \n
            listAddNodeHead(event->heads, line);
            buf = ++p;
            in_eof = 1;
        } else {
            in_eof = 0;
            p++;
        }
    }
    
    return p;
}

static void parse_body(Event *event, char *buf)
{
    int len = 0;
    char *p = buf;
    while(p && *p) p++;
    len = p - buf;
    if(len) {
        event->body = sdsnewlen(buf, len);
    }
}

static void strfree(void *s) {
    sdsfree( (sds) s);
}


