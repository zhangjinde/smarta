#ifndef __CONFIG_H
#define __CONFIG_H

#if defined(__APPLE__)

	#define OSNAME "macosx"

#elif defined(__linux__)

	#define OSNAME "linux"

#elif defined(__freebsd__)

	#define OSNAME "freebsd"

#elif defined(__FreeBSD__)

	#define OSNAME "freebsd"

#endif

#ifdef __APPLE__
#include <AvailabilityMacros.h>
#endif

/* Test for proc filesystem */
#ifdef __linux__
#define HAVE_PROCFS 1
#endif

/* Test for task_info() */
#if defined(__APPLE__)
#define HAVE_TASKINFO 1
#endif

/* Test for backtrace() */
#if defined(__APPLE__) || defined(__linux__)
#define HAVE_BACKTRACE 1
#endif

/* Test for polling API */
#ifdef __linux__
#define HAVE_EPOLL 1
#endif

#if (defined(__APPLE__) && defined(MAC_OS_X_VERSION_10_6)) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined (__NetBSD__)
#define HAVE_KQUEUE 1
#endif

/* Define aof_fsync to fdatasync() in Linux and fsync() for all the rest */
#ifdef __linux__
#define aof_fsync fdatasync
#else
#define aof_fsync fsync
#endif

#endif
