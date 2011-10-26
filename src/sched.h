#ifndef __SCHED_H
#define __SCHED_H

#include "ae.h"
#include "list.h"

void sched_run(aeEventLoop *el, list *services);

#endif /* __SCHED_H__ */
