#!/bin/bash

#
# @test
# @requires var.rh.jdk == "true"
# @bug 1897602
# @summary Warnings when using ManagementFactory.getPlatformMBeanServer with -Xcheck:jni VM argument
# @requires jdk.version.major > 8
# @run shell TestDiagnosticCommandImpl.sh

# Note, that on jdk8, this fails with differen trace then the original issue was hiting:
# https://bugzilla.redhat.com/show_bug.cgi?id=1897602
# > As for https://bugs.openjdk.java.net/browse/JDK-8260436, it s already in
# > 11u. Any plans with 8u?
# No, it's not an issue there.
# Different bug.
# $ /usr/lib/jvm/java-1.8.0-openjdk/bin/java -Xcheck:jni TestDiagnosticCommandImpl 
# WARNING in native method: JNI call made without checking exceptions when required to from CallStaticObjectMethod
# ...
# Fixed in later JDKs with:
# https://hg.openjdk.java.net/jdk-updates/jdk11u-dev/rev/a16236cd61d7
# ...
# thus requires jdk.version.major > 8...


if [ "x${TESTSRC}" = "x" ] ; then
  TESTSRC=.
fi

if [ "${TESTJAVA}" = "" ] ; then
  PATH_JAVA=$(readlink -f $(which javac))
  TESTJAVA=$(dirname $(dirname ${PATH_JAVA}))
  echo "TESTJAVA not set, selecting " ${TESTJAVA}
  echo "If this is incorrect, try setting the variable manually."
fi

if [ "${TESTSRC}" = "" ] ; then
  TESTSRC="."
fi

# set platform-dependent variables
OS=`uname -s`
case "$OS" in
  Linux )
    PS=":"
    FS="/"
    ;;
  Windows_* | CYGWIN_NT* )
    PS=";"
    FS="\\"
    ;;
  * )
    echo "Unrecognized system!"
    exit 1;
    ;;
esac

if $TESTJAVA/bin/java -version 2>&1 | grep '1[.]8[.]0' ; then
  EXTFLAGS=""
else
  EXTFLAGS='--add-modules jdk.crypto.cryptoki,java.base --add-exports jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED --add-opens jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED --add-exports java.base/javax.crypto=ALL-UNNAMED --add-opens java.base/javax.crypto=ALL-UNNAMED'
fi


set -exo pipefail

$TESTJAVA/bin/javac $EXTFLAGS -d . $TESTSRC/TestDiagnosticCommandImpl.java
$TESTJAVA/bin/java $EXTFLAGS -Xcheck:jni TestDiagnosticCommandImpl 2>&1 | tee TestDiagnosticCommandImpl.out

sed -i 's;.*warning.*jfr.*LeakProfiler .*;jfr issue removed, see runner;g' TestDiagnosticCommandImpl.out
sed -i 's;.*Warning: SIGPIPE handler.*;SIGPIPE issue removed, see runner;g' TestDiagnosticCommandImpl.out

if cat TestDiagnosticCommandImpl.out | grep -i -e WARNING ; then
  echo failed
  exit 1
else
  echo passed
  exit 0
fi


