AC_PREREQ(2.59)

AC_INIT([netmgmt], [1.2.0], [support@vmware.com])
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_CONFIG_TESTDIR(tests)

AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_MACRO_DIR([m4])
m4_pattern_allow([AM_PROG_AR])
AM_PROG_AR

AC_PROG_CC
AC_PROG_LIBTOOL

dnl Check supported operating systems
dnl

case "${host_os}:${host_cpu}" in

    linux*:x86_64)
	;;
    linux*:aarch64)
        ;;
    *)
        AC_ERROR("Unsupported operating system - ${host_os}:${host_cpu}")
        ;;
esac

CPPFLAGS="$CPPFLAGS -D_REENTRANT -D_GNU_SOURCE -fPIC"

AM_CPPFLAGS="$AM_CPPFLAGS -I${top_srcdir}/include"
AM_CFLAGS="$AM_CFLAGS -Wall -Werror -fno-strict-aliasing"

AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)

AC_ARG_ENABLE([debug],
    [AC_HELP_STRING([--enable-debug], [enable debugging (default: disabled)])],
    [
        if test x"$enableval" = x"yes"
        then
            AM_CFLAGS="$AM_CFLAGS -g -O0"
            AM_CPPFLAGS="$AM_CPPFLAGS -DDEBUG -DLDAP_DEBUG"
        fi
    ])

AC_HEADER_STDC
AC_CHECK_HEADERS(pthread.h errno.h sys/types.h stdio.h string.h strings.h)
AC_CHECK_HEADERS(unistd.h time.h inttypes.h sys/socket.h netdb.h syslog.h)
AC_CHECK_HEADERS(stdlib.h locale.h stddef.h stdarg.h assert.h signal.h)
AC_CHECK_HEADERS(ctype.h netinet/in.h stdint.h)

AC_C_CONST
AC_TYPE_SIZE_T

AC_CHECK_FUNCS(strerror)

AC_CHECK_LIB([dl], [dlopen], [DL_LIBS="-ldl"])
AC_CHECK_LIB([pthread], [pthread_self], [PTHREAD_LIBS="-lpthread"])

PKG_CHECK_MODULES([GLIB], [glib-2.0], [have_libglib=yes], [have_libglib=no])
AM_CONDITIONAL([GLIB],  [test "$have_libglib" = "yes"])

AC_SUBST(DL_LIBS)
AC_SUBST(PTHREAD_LIBS)

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

AC_CONFIG_FILES([Makefile
                 common/Makefile
                 cli/Makefile
                 src/Makefile
                 tools/Makefile
                 tools/netmgr/Makefile
                 tests/Makefile
                 tests/apitest/Makefile
                ])
AC_OUTPUT

