#ifndef __EVENT_H
#define __EVENT_H

#include "list.h"

typedef struct _Event {
    char *status;
    char *service;
    char *subject;
    list *heads;
    char *body;
} Event;

Event *event_new();

void event_free(Event *event);

Event *event_parse(char *buf);

#endif
