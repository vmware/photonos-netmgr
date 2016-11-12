# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
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
	} >'$(srcdir)/package.m4'


TESTSUITE = $(srcdir)/testsuite
EXTRA_DIST = init.at $(srcdir)/package.m4 $(TESTSUITE)

#testsuites
TESTSUITE_AT = testsuite.at
TESTSUITE_AT += version.at
EXTRA_DIST += $(TESTSUITE_AT)

DISTCLEANFILES = atconfig testsuite

check-local: atconfig $(TESTSUITE)
	systemctl start docker && pushd $(top_srcdir) && \
	if docker ps | grep netmgr_unittest > /dev/null; \
          then docker kill netmgr_unittest; \
        fi && \
	if docker ps -a | grep netmgr_unittest > /dev/null; \
          then docker rm netmgr_unittest; \
        fi && \
	docker build -t netmgr_ut . && \
	docker run -d --name netmgr_unittest --privileged --cap-add=SYS_ADMIN \
            --cap-add=NET_ADMIN --security-opt seccomp=unconfined \
            --stop-signal=SIGRTMIN+3 --tmpfs --cap-add=/run --tmpfs /run/lock \
            -v /sys/fs/cgroup:/sys/fs/cgroup:ro netmgr_ut && sleep 2 && \
	docker exec -ti netmgr_unittest /netmgr/run_tests.sh && sleep 2 && \
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
$(TESTSUITE): $(srcdir)/package.m4 init.at $(TESTSUITE_AT)
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
