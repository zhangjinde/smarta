
#include <stdio.h>
#include <stdlib.h>
#include "smarta.h"

extern Smarta smarta;

void smarta_ctl_status() {
	char pid[20];
	FILE *fp = fopen(smarta.pidfile, "r");
	if(!fp) {
		fprintf(stderr, "Smarta is not running.\n");
		return;
	}
	fgets(pid, 20, fp);
	printf("Smarta is running as pid %s\n", pid);
}

void smarta_ctl_stop() 
{
	int status;
	FILE *fp = fopen(smarta.pidfile, "r");
	if(!fp) {
		fprintf(stderr, "Smarta is not running.\n");
		return;
	}
	status = system("kill `cat smarta.pid`");
	if(status == 0) {
		printf("Smarta is stopped.\n");
	}
}

