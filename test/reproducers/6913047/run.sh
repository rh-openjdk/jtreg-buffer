#!/bin/bash
# Purpose of this wrapper is implementation on Windows. For successful run is necessary to and NSPR libraries, NSS libraries and set up PATH in a corresponding way

set -x
set -e

if [ -e /proc/sys/crypto/fips_enabled ] && [ 1 = "$( cat /proc/sys/crypto/fips_enabled )" ] ; then
    # ignorred on fips since test manually configures and adds pkcs11 provider
    echo "test ignored"
    exit 0
fi

OS=$(uname -s)
IS_WINDOWS=FALSE
case "$OS" in
  Windows_* | CYGWIN_NT* )
    IS_WINDOWS=TRUE
    ;;
esac

if [ "${TESTJAVA}" = "" ]; then
  PATH_JAVA=$(readlink -f "$(which javac)")

  if [ $IS_WINDOWS = 'TRUE' ]; then
    TESTJAVA=$(dirname "$(dirname "$(cygpath -m "$PATH_JAVA")")")
  else
    TESTJAVA=$(dirname $(dirname ${PATH_JAVA}))
  fi

  echo "TESTJAVA not set, selecting " ${TESTJAVA}
  echo "If this is incorrect, try setting the variable manually."
fi

FS="/"
JAVAC=${TESTJAVA}${FS}bin${FS}javac
JAVA=${TESTJAVA}${FS}bin${FS}java

if [ $IS_WINDOWS = 'TRUE' ]; then
  JAVAC=$(cygpath -m "$JAVAC")
  JAVA=$(cygpath -m "$JAVA")
fi

if $TESTJAVA/bin/java -version 2>&1 | grep '1[.]8[.]0' ; then
  EXTFLAGS=""
else
  EXTFLAGS='--add-modules jdk.crypto.cryptoki,java.base --add-exports jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED --add-opens jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED --add-exports java.base/javax.crypto=ALL-UNNAMED --add-opens java.base/javax.crypto=ALL-UNNAMED'
fi

if [ "${TESTSRC}" = "" ]; then
  TESTSRC=.
  if [ $IS_WINDOWS = 'TRUE' ]; then
    TESTSRC=$(cygpath -m $(readlink -f "."))
  fi
fi

WIN_NSS_PATH="$PWD/win-nss"

if [ $IS_WINDOWS = 'TRUE' ]; then
  WIN_NSS_PATH_CYGWIN=$(cygpath "$WIN_NSS_PATH")
  tar -xvf $(cygpath $TESTSRC/win-nss.tar.xz)
  chmod 777 -R "$WIN_NSS_PATH_CYGWIN"
  # cygpath has to be exactly in this way
  export PATH="$WIN_NSS_PATH_CYGWIN:$PATH"
fi

"$JAVAC" -d . $TESTSRC/Bug6913047.java $EXTFLAGS
R=$?
if [ "0$R" -ne "0" ]; then
  echo "Compilation failed"
  exit $R
else
  echo "Compilation successful"
fi
"$JAVA" "-Dtest.src=$TESTSRC" "-Dtest.nssLibDir=$(cygpath -m $WIN_NSS_PATH)" $EXTFLAGS Bug6913047
