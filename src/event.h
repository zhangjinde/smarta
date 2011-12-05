#ifndef __EVENT_H
#define __EVENT_H

#include "list.h"

#define UNKNOWN -1
#define OK 0
#define INFO 1
#define WARNING 2
#define CRITICAL 3

#define ACTIVE 1
#define PASSIVE 2

typedef struct _Event {
    int status;
    char *sensor;
    int sensortype;
    char *title;
    char *body;
    list *heads;
} Event;

Event *event_new();

char *event_status(Event *event);

int event_has_heads(Event *event);

sds event_heads_to_string(Event *event);

sds event_metrics_to_string(Event *event);

void event_free(Event *event);

Event *event_feed(char *buf);

#endif

