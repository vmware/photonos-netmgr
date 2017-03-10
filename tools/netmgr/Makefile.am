bin_PROGRAMS = netmgr

netmgr_SOURCES = \
    main.c

netmgr_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/include/public


netmgr_LDADD = \
    @top_builddir@/common/libcommon.la \
    @top_builddir@/cli/libnetmgrcli.la \
    $(top_builddir)/src/libnetmgr.la
