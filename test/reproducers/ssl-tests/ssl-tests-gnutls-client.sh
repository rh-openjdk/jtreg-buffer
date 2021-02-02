#!/bin/sh
# @test
# @bug 6666666
# @summary ssl-test with gnutls client
# @run shell/timeout=1000 ssl-tests-gnutls-client.sh

set -eu

osSupported() {
    if ! [ -f /etc/redhat-release ] ; then
        return 1
    fi
    rhelPattern='^Red Hat Enterprise Linux release ([0-9]+)\..*$'
    if cat /etc/redhat-release | grep -E -q "${rhelPattern}" ; then
        version="$(  cat /etc/redhat-release | grep -E "${rhelPattern}" \
        | head -n 1  | sed -E "s/${rhelPattern}/\\1/g" )"
        if [ "${version}" -ge 8 ] ; then
            return 0
        fi
    fi
    if cat /etc/redhat-release | grep -q "Fedora" ; then
        return 0
    fi
    return 1
}

if ! osSupported ; then
    echo "ssl-tests with openssl client are not supported on this os yet!" 1>&2
    exit 0
fi

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

# see: https://bugzilla.redhat.com/show_bug.cgi?id=1918473
serverShutdownOutputParam="SSLTESTS_SERVER_SHUTDOWN_OUTPUT=1"

cd "ssl-tests"
make clean && make ${fipsParam} ${ignoredProtoParam} ${serverShutdownOutputParam} SSLTESTS_USE_GNUTLS_CLIENT=1