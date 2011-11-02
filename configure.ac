AC_INIT([smarta], [trunk], [ery.lee@gmail.com])
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_CC_C_O

AC_CHECK_HEADER(openssl/ssl.h, [], [AC_MSG_ERROR([couldn't find openssl headers, openssl required])])

AC_CHECK_FUNCS(memmove)
AC_C_BIGENDIAN([byteorder=1234], [byteorder=4321], [], [])

with_parser=builtin
PARSER_NAME=expat
PARSER_CFLAGS=\$\(builtin_CFLAGS\)
PARSER_LIBS=\$\(builtin_LIBS\)

AC_MSG_NOTICE([smarta will use the $with_parser XML parser])
AC_SEARCH_LIBS([socket], [socket])

AM_CONDITIONAL([BUILD_EXPAT], [test x$with_parser = xbuiltin])
AC_DEFINE_UNQUOTED([BYTEORDER], [$byteorder])
AC_SUBST(PARSER_NAME)                              
AC_SUBST(PARSER_CFLAGS)
AC_SUBST(PARSER_LIBS)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
