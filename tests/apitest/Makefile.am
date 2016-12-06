# Unit tests for netmgr APIs and helper functions.


#TESTS = testnetmgr # testutils

check_PROGRAMS = testnetmgr testutils

testnetmgr_SOURCES = testnetmgr.c utils.c
testnetmgr_CFLAGS = \
	@CHECK_CFLAGS@ \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/public
testnetmgr_LDADD = \
    @CHECK_LIBS@ \
    $(top_builddir)/common/libcommon.la \
    $(top_builddir)/src/libnetmgr.la

testutils_SOURCES = testutils.c $(top_srcdir)/include/public/netmgr.h
testutils_CFLAGS = \
	@CHECK_CFLAGS@ \
	-I$(top_srcdir)/include/public \
	-I$(top_srcdir)/src
testutils_LDADD = \
    @CHECK_LIBS@ \
    $(top_builddir)/common/libcommon.la \
    $(top_builddir)/src/libnetmgr.la

