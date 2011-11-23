#ifndef __PLUGIN_H
#define __PLUGIN_H

typedef int (*Check)(int argc, char **argv, char *result, int *size);

typedef struct _Plugin {
    char *name;
    char *vsn;
    char *usage;
    Check check;
} Plugin;

typedef Plugin* (*PluginInfo)();

#endif

