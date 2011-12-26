#ifndef __CJOB_H
#define __CJOB_H

#include "bitstring.h"

#include "sds.h"

typedef int time_min;

#define SECONDS_PER_MINUTE 60

#define FIRST_MINUTE    0
#define LAST_MINUTE     59
#define MINUTE_COUNT    (LAST_MINUTE - FIRST_MINUTE + 1)

#define FIRST_HOUR      0
#define LAST_HOUR       23
#define HOUR_COUNT      (LAST_HOUR - FIRST_HOUR + 1)

#define FIRST_DOM       1
#define LAST_DOM        31
#define DOM_COUNT       (LAST_DOM - FIRST_DOM + 1)

#define FIRST_MONTH     1
#define LAST_MONTH      12
#define MONTH_COUNT     (LAST_MONTH - FIRST_MONTH + 1)

/* note on DOW: 0 and 7 are both Sunday, for compatibility reasons. */
#define FIRST_DOW       0
#define LAST_DOW        7
#define DOW_COUNT       (LAST_DOW - FIRST_DOW + 1)

#define PPC_NULL        ((char **)NULL)

#define TP_OK         0
#define TP_ERR        (-1)

typedef enum _TpErr {
	TP_ERR_NONE = 0,
	TP_ERR_MINUTE,
	TP_ERR_HOUR,
	TP_ERR_DOM,
	TP_ERR_MONTH,
	TP_ERR_DOW
} TpErr;

typedef struct _TimePeriod {
	char			*name;
	bitstr_t        bit_decl(minute, MINUTE_COUNT);
	bitstr_t        bit_decl(hour,   HOUR_COUNT);
	bitstr_t        bit_decl(dom,    DOM_COUNT);
	bitstr_t        bit_decl(month,  MONTH_COUNT);
	bitstr_t        bit_decl(dow,    DOW_COUNT);
	int             flags;
#define DOM_STAR        0x01
#define DOW_STAR        0x02
#define WHEN_REBOOT     0x04
#define MIN_STAR        0x08
#define HR_STAR         0x10
} TimePeriod;

typedef struct _CronJob {
	int             sensorid;
	TimePeriod		*tp;
} CronJob;

CronJob *cronjob_new();

TimePeriod *timeperiod_new();

void timeperiod_free();

char *timeperiod_err(int e);

int timeperiod_feed(TimePeriod *tp, int argc, sds *argv);

int timeperiod_ready(TimePeriod *tp);

void cronjob_free(CronJob *job);

#endif
