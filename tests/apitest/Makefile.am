# Unit tests for netmgr APIs and helper functions.


#TESTS = testnetmgr # testutils

check_PROGRAMS = testnetmgr testutils

testnetmgr_SOURCES = testnetmgr.c
testnetmgr_CFLAGS = \
	@CFLAGS@ \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/public
testnetmgr_LDADD = \
    $(top_builddir)/common/libcommon.la \
    $(top_builddir)/src/libnetmgr.la

testutils_SOURCES = testutils.c $(top_srcdir)/include/public/netmgr.h
testutils_CFLAGS = \
	@CFLAGS@ \
	-I$(top_srcdir)/include/public \
	-I$(top_srcdir)/src
testutils_LDADD = \
    $(top_builddir)/common/libcommon.la \
    $(top_builddir)/src/libnetmgr.la

