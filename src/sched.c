
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "xmpp.h"
#include "sched.h"
#include "smarta.h"
#include "list.h"
#include "logger.h"

#define MAX_INPUT_BUFFER 4096

static int check_service(struct aeEventLoop *el, long long id, void *clientdata);

void sched_run(aeEventLoop *el, list *services) {
    long taskid;
    int delay = 0;
    listNode *node;
    Service *service;
    listIter *iter = listGetIterator(services, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        delay = (random() % 300) * 1000;
        service = (Service *)node->value;
        logger_debug("sched", "schedule service '%s' after %d seconds", 
            service->name, delay/1000);
        taskid = aeCreateTimeEvent(el, delay, check_service, service, NULL);
        service->taskid = taskid;
    }
}

int check_service(struct aeEventLoop *el, long long id, void *clientdata) {
    Service *service = (Service *)clientdata;
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
        logger_debug("sched", "check service: %s\n", service->name);
        raw_command = sdscat(raw_command, service->command);
        fp = popen(raw_command, "r");
        while(fgets(output_buffer, sizeof(output_buffer) - 1, fp)) {
            result = sdscat(result, output_buffer);
        }
        pclose(fp);
        logger_debug("sched", "check result:\n %s", result);
        sdsfree(result);
        exit(0);
    } else {//current
        //FIXME: later
    }

    return service->period;
}

