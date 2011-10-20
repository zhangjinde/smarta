
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "xmpp.h"
#include "util.h"

/* version information */

#ifndef LIBXMPP_VERSION_MAJOR
/** @def LIBXMPP_VERSION_MAJOR
 *  The major version number of Strophe.
 */
#define LIBXMPP_VERSION_MAJOR (0)
#endif
#ifndef LIBXMPP_VERSION_MINOR
/** @def LIBXMPP_VERSION_MINOR
 *  The minor version number of Strophe.
 */
#define LIBXMPP_VERSION_MINOR (0)
#endif

/** Initialize the Strophe library.
 *  This function initializes subcomponents of the Strophe library and must
 *  be called for Strophe to operate correctly.
 *
 *  @ingroup Init
 */
 void xmpp_initialize(void)
{
    sock_initialize();
    tls_initialize();
}

/** Shutdown the Strophe library.
 *
 *  @ingroup Init
 */
void xmpp_shutdown(void)
{
    tls_shutdown();
    sock_shutdown();
}

/** Check that Strophe supports a specific API version.
 *
 *  @param major the major version number
 *  @param minor the minor version number
 *
 *  @return TRUE if the version is supported and FALSE if unsupported
 *
 *  @ingroup Init
 */
int xmpp_version_check(int major, int minor)
{
    return (major == LIBXMPP_VERSION_MAJOR) &&
	   (minor >= LIBXMPP_VERSION_MINOR);
}

/* We define the global default allocator, logger, and context here. */

/* Wrap stdlib routines malloc, free, and realloc for default memory 
 * management. 
 */
static void *_malloc(const size_t size, void * const userdata)
{
    return malloc(size);
}

static void _free(void *p, void * const userdata)
{
    free(p);
}

static void *_realloc(void *p, const size_t size, void * const userdata)
{
    return realloc(p, size);
}

/* default memory function map */
static xmpp_mem_t xmpp_default_mem = {
    _malloc, /* use the thinly wrapped stdlib routines by default */
    _free,
    _realloc,
    NULL
};

/* log levels and names */
static const char * const _xmpp_log_level_name[4] = {"DEBUG", "INFO", "WARN", "ERROR"};
static const xmpp_log_level_t _xmpp_default_logger_levels[] = {XMPP_LEVEL_DEBUG,
							       XMPP_LEVEL_INFO,
							       XMPP_LEVEL_WARN,
							       XMPP_LEVEL_ERROR};

/** Log a message.
 *  The default logger writes to stderr.
 *
 *  @param userdata the opaque data used by the default logger.  This contains
 *      the filter level in the default logger.
 *  @param level the level to log at
 *  @param area the area the log message is for
 *  @param msg the log message
 */
void xmpp_default_logger(void * const userdata,
			 const xmpp_log_level_t level,
			 const char * const area,
			 const char * const msg)
{
    xmpp_log_level_t filter_level = * (xmpp_log_level_t*)userdata;
    if (level >= filter_level)
	fprintf(stderr, "%s %s %s\n", area, _xmpp_log_level_name[level], msg);
}

static const xmpp_log_t _xmpp_default_loggers[] = {
	{&xmpp_default_logger, (void*)&_xmpp_default_logger_levels[XMPP_LEVEL_DEBUG]},
	{&xmpp_default_logger, (void*)&_xmpp_default_logger_levels[XMPP_LEVEL_INFO]},
	{&xmpp_default_logger, (void*)&_xmpp_default_logger_levels[XMPP_LEVEL_WARN]},
	{&xmpp_default_logger, (void*)&_xmpp_default_logger_levels[XMPP_LEVEL_ERROR]}
};

/** Get a default logger with filtering.
 *  The default logger provides a basic logging setup which writes log
 *  messages to stderr.  Only messages where level is greater than or
 *  equal to the filter level will be logged.
 *
 *  @param level the highest level the logger will log at
 *
 *  @return the log structure for the given level
 *
 *  @ingroup Context
 */
xmpp_log_t *xmpp_get_default_logger(xmpp_log_level_t level)
{
    /* clamp to the known range */
    if (level > XMPP_LEVEL_ERROR) level = XMPP_LEVEL_ERROR;
    if (level < XMPP_LEVEL_DEBUG) level = XMPP_LEVEL_DEBUG;

    return (xmpp_log_t*)&_xmpp_default_loggers[level];
}

static xmpp_log_t xmpp_default_log = { NULL, NULL };

/** Create and initialize a Strophe context object.
 *  If mem is NULL, a default allocation setup will be used which
 *  wraps malloc(), free(), and realloc() from the standard library.
 *  If log is NULL, a default logger will be used which does no
 *  logging.  Basic filtered logging to stderr can be done with the
 *  xmpp_get_default_logger() convenience function.
 *
 *  @param mem a pointer to an xmpp_mem_t structure or NULL
 *  @param log a pointer to an xmpp_log_t structure or NULL
 *
 *  @return the allocated Strophe context object or NULL on an error
 *
 *  @ingroup Context
 */
xmpp_ctx_t *xmpp_ctx_new(const xmpp_mem_t * const mem, 
			 const xmpp_log_t * const log)
{
    xmpp_ctx_t *ctx = NULL;

    if (mem == NULL)
	ctx = xmpp_default_mem.alloc(sizeof(xmpp_ctx_t), NULL);
    else
	ctx = mem->alloc(sizeof(xmpp_ctx_t), mem->userdata);

    if (ctx != NULL) {
	ctx->connlist = NULL;
	ctx->loop_status = XMPP_LOOP_NOTSTARTED;
    }

    return ctx;
}

/** Free a Strophe context object that is no longer in use.
 *
 *  @param ctx a Strophe context object
 *
 *  @ingroup Context
 */
void xmpp_ctx_free(xmpp_ctx_t * const ctx) {
    /* mem and log are owned by their suppliers */
    free(ctx); /* pull the hole in after us */
}

