#!/bin/sh
# @test
# @bug 6666666
# @summary ssl-test with nss client
# @run shell/timeout=1000 ssl-tests-nss-client.sh

set -eu

fipsParam=""
ignoredProtoParam="SSLTESTS_IGNORE_PROTOCOLS=SSLv3"
if [ -e /proc/sys/crypto/fips_enabled ] && [ 1 = "$( cat /proc/sys/crypto/fips_enabled )" ] ; then
    fipsParam="TEST_PKCS11_FIPS=1 SSLTESTS_CUSTOM_JAVA_PARAMS=-Djdk.tls.ephemeralDHKeySize=2048"
    # ignore protocols not supported in fips mode
    ignoredProtoParam="${ignoredProtoParam}|TLSv1|TLSv1.1"
    if printf '%s' "${TESTJAVA:-}" | grep -q 'upstream' ; then
        # upstream misses the patch to disable TLSv1.3 in fips mode
        # (not supported by pkcs11 provider)
        ignoredProtoParam="${ignoredProtoParam}|TLSv1.3"
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

cd "ssl-tests"
make clean && make ${fipsParam} ${ignoredProtoParam} SSLTESTS_USE_NSS_CLIENT=1