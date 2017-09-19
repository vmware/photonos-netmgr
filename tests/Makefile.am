# The `:;' works around a Bash 3.2 bug when the output is not writeable.

ABSTOPDIR = `realpath $(PWD)/../../`
clitestdir = $(srcdir)/clitest

$(clitestdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
	echo '# Signature of the current package.' && \
	echo 'm4_define([AT_PACKAGE_NAME],' && \
	echo '  [$(PACKAGE_NAME)])' && \
	echo 'm4_define([AT_PACKAGE_TARNAME],' && \
	echo '  [$(PACKAGE_TARNAME)])' && \
	echo 'm4_define([AT_PACKAGE_VERSION],' && \
	echo '  [$(PACKAGE_VERSION)])' && \
	echo 'm4_define([AT_PACKAGE_STRING],' && \
	echo '  [$(PACKAGE_STRING)])' && \
	echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
	echo '  [$(PACKAGE_BUGREPORT)])'; \
	echo 'm4_define([AT_PACKAGE_URL],' && \
	echo '  [$(PACKAGE_URL)])'; \
	} >'$(clitestdir)/package.m4'

SUBDIRS = \
    apitest

TESTSUITE = $(clitestdir)/testsuite
EXTRA_DIST = $(clitestdir)/init.at $(clitestdir)/package.m4 $(TESTSUITE)

#testsuites
TESTSUITE_AT = $(clitestdir)/testsuite.at
TESTSUITE_AT += $(clitestdir)/version.at
EXTRA_DIST += $(TESTSUITE_AT)

DISTCLEANFILES = atconfig $(clitestdir)/testsuite

check-local: atconfig $(TESTSUITE)
	systemctl start docker && pushd $(top_srcdir) && \
	if docker ps | grep netmgr_unittest > /dev/null; \
          then docker kill netmgr_unittest; \
        fi && \
	if docker ps -a | grep netmgr_unittest > /dev/null; \
          then docker rm netmgr_unittest; \
        fi && \
	docker build --build-arg NMROOT=$(ABSTOPDIR) -t netmgr_ut . && \
	docker run -d --name netmgr_unittest --privileged --cap-add=SYS_ADMIN \
            --cap-add=NET_ADMIN --security-opt seccomp=unconfined \
            --stop-signal=SIGRTMIN+3 --tmpfs /run --tmpfs /run/lock \
            -v /sys/fs/cgroup:/sys/fs/cgroup:ro netmgr_ut && sleep 2 && \
	docker exec -ti netmgr_unittest /netmgr/unittest/run_tests.sh && \
	docker kill netmgr_unittest && docker rm netmgr_unittest && \
	echo "Done!"

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(abs_top_srcdir)/tools/netmgr' \
	$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
	$(SHELL) '$(TESTSUITE)' --clean
	rm -rf testroot

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(clitestdir)/package.m4 $(clitestdir)/init.at $(TESTSUITE_AT)
	$(AUTOTEST) -I '$(clitestdir)' -o $@.tmp $@.at
	mv $@.tmp $@
