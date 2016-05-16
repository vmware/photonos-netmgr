lib_LTLIBRARIES = libnetmgr.la

libnetmgr_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/include/public
AM_CFLAGS += $(GLIB_CFLAGS)

libnetmgr_la_SOURCES = \
    iniparser.c \
    netmgr.c

libnetmgr_la_LIBADD = \
    @top_builddir@/common/libcommon.la \
    -lglib-2.0
