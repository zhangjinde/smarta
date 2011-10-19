
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sds.h"
#include "smarta.h"

/*-----------------------------------------------------------------------------
 * Config file parsing
 *----------------------------------------------------------------------------*/

#define CONFIGLINE_MAX 1024
#define IN_SMARTA_BLOCK 1
#define IN_SERVICE_BLOCK 2
#define IN_COMMADN_BLOCK 3

int yesnotoi(char *s) {
    if (!strcasecmp(s,"yes")) return 1;
    else if (!strcasecmp(s,"no")) return 0;
    else return -1;
}

void load_config(char *filename) {
    FILE *fp;
    char buf[CONFIGLINE_MAX+1], *err = NULL;
    int linenum = 0;
    sds line = NULL;
    int really_use_vm = 0;
    int state;
    service_t *service;

    if ((fp = fopen(filename,"r")) == NULL) {
        //redisLog(REDIS_WARNING, "Fatal error, can't open config file '%s'", filename);
        printf("Fatal error, can't open config file '%s'", filename);
        exit(1);
    }

    while(fgets(buf,CONFIGLINE_MAX+1,fp) != NULL) {
        sds *argv;
        int argc, j;
        sds cmd;

        linenum++;
        line = sdsnew(buf);
        line = sdstrim(line," \t\r\n");

        /* Skip comments and blank lines*/
        if (line[0] == '#' || line[0] == '\0') {
            sdsfree(line);
            continue;
        }

        /* Split into arguments */
        argv = sdssplitargs(line,&argc);
        sdstolower(argv[0]);

        /* Execute config directives */
        if (!strcasecmp(argv[0],"smarta") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_SMARTA_BLOCK;
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0], "}") && argv == 1) {
            printf("smarta.name: %s\n", smarta.name);
            printf("smarta.server: %s\n", smarta.server);
            printf("smarta.apikey: %s\n\n", smarta.apikey);
            state = 0;
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0], "}") && argv == 1) {
            printf("service.name: %s", service->name);
            printf("service.period: %d", service->period);
            printf("service.command: %d", service->command);
            state = 0;
        } else if (!strcasecmp(argv[0],"service") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_SERVICE_BLOCK;
            service = malloc(sizeof(service_t));
        } else if (!strcasecmp(argv[0],"command") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_COMMAND_BLOCK;
            command = malloc(sizeof(command_t));
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"name") && argc == 2) {
            smarta.name = zstrdup(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"server") && argc == 2) {
            smarta.server = zstrdup(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"apikey") && argc == 2) {
            smarta.apikey = zstrdup(argv[1]);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"name") && argc == 2) {
            service->name = zstrdup(argv[1]);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"period") && argc == 2) {
            service->period = atoi(argv[1]);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"command") && argc == 2) {
            service->command = zstrdup(argv[1]);
        } else {
            err = "Bad directive or wrong number of arguments"; goto loaderr;
        }
        for (j = 0; j < argc; j++)
            sdsfree(argv[j]);
        zfree(argv);
        sdsfree(line);
    }
    fclose(fp);
    return;

loaderr:
    fprintf(stderr, "\n*** FATAL CONFIG FILE ERROR ***\n");
    fprintf(stderr, "Reading the configuration file, at line %d\n", linenum);
    fprintf(stderr, ">>> '%s'\n", line);
    fprintf(stderr, "%s\n", err);
    exit(1);
}

