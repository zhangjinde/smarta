
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "xmpp.h"

void xmpp_log(int level, const char *fmt, ...) {
    const char *c = ".-*#";
    time_t now = time(NULL);
    va_list ap;
    FILE *fp;
    char buf[64];
    char msg[MAX_LOGMSG_LEN];

    //if (level < smarta.verbosity) return;

    //fp = (smarta.logfile == NULL) ? stdout : fopen(smarta.logfile,"a");
    fp = stdout;
    if (!fp) return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    strftime(buf,sizeof(buf),"%d %b %H:%M:%S",localtime(&now));
    fprintf(fp,"%s %c %s\n",buf,c[level],msg);
    fflush(fp);

    //if (smarta.logfile) fclose(fp);
}
