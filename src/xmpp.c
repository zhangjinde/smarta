
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

