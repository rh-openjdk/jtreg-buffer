#!/usr/bin/bash

set -e
set -x

FS="/"
JAVAC=${TESTJAVA}${FS}bin${FS}javac
JAVA=${TESTJAVA}${FS}bin${FS}java

if [ "x$TESTSRC" == x ] ; then
  TESTSRC=.
fi

if $JAVA -version 2>&1 | grep '1[.]8[.]0' ; then
  FLAGS=""
else
  # this is needed for ojdk 16 and above
  FLAGS="--add-modules jdk.crypto.cryptoki --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED"
fi


# only testing whether the Test.java is buildable, dont need to run it (see bug)
${JAVAC} -d . $FLAGS ${TESTSRC}/Test.java
