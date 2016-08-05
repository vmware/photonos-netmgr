bin_PROGRAMS = netmgr

netmgr_SOURCES = \
    main.c \
    parseargs.c

netmgr_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/include/public \
    -I$(top_srcdir)/cli


netmgr_LDADD = \
    @top_builddir@/common/libcommon.la \
    @top_builddir@/cli/libnetmgrcli.la \
    $(top_builddir)/src/libnetmgr.la
