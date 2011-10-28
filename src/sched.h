#ifndef __SCHED_H
#define __SCHED_H

#include "ae.h"
#include "list.h"

void sched_run(aeEventLoop *el, list *services);

void sched_check_result(aeEventLoop *el, int fd, void *privdata, int mask);

#endif /* __SCHED_H__ */
