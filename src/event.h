#ifndef __EVENT_H
#define __EVENT_H

#include "list.h"

typedef struct _Event {
    char *status;
    char *sensor;
    char *subject;
    list *heads;
    char *body;
} Event;

Event *event_new();

int event_has_heads(Event *event);

sds event_heads_to_string(Event *event);

sds event_metrics_to_string(Event *event);

void event_free(Event *event);

Event *event_parse(char *buf);

int event_intstatus(Event *event);

#endif
