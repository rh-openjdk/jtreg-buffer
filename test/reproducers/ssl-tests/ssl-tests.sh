#!/bin/sh
# @test
# @bug 6666666
# @summary ssl-test
# @run shell/timeout=1000 ssl-tests.sh

set -eu

fipsParam=""
ignoredProtoParam=""
if [ -e /proc/sys/crypto/fips_enabled ] && [ 1 = "$( cat /proc/sys/crypto/fips_enabled )" ] ; then
    fipsParam="TEST_PKCS11_FIPS=1 SSLTESTS_CUSTOM_JAVA_PARAMS=-Djdk.tls.ephemeralDHKeySize=2048"
    if printf '%s' "${TESTJAVA:-}" | grep 'upstream' ; then
        # upstream misses the patch to disable TLSv1.3 in fips mode
        # (not supported by pkcs11 provider)
        ignoredProtoParam="SSLTESTS_IGNORE_PROTOCOLS=TLSv1.3"
    fi
fi

if [ -n "${TESTJAVA:-}" ]; then
    export JAVA_HOME="${TESTJAVA}"
fi

if ! [ -d "ssl-tests" ] ; then
    if [ -n "${TESTSRC:-}" ] && [ -d "${TESTSRC}/ssl-tests" ] ; then
        cp -a "${TESTSRC}/ssl-tests" .
    else
        git clone "https://github.com/zzambers/ssl-tests.git"
    fi
fi

# kerberos seems to need more complicated setup, not yet implemented (ignore for now):
# https://hg.openjdk.java.net/jdk8u/jdk8u/jdk/file/d5c320d784e5/test/sun/security/krb5/auto/SSL.java
krbIgnoreParam="SSLTESTS_IGNORE_CIPHERS=TLS_KRB5.*"

cd "ssl-tests"
make clean && make ${krbIgnoreParam} ${fipsParam} ${ignoredProtoParam}
