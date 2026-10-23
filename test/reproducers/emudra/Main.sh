#!/bin/bash

set -exu
if set -o | grep pipefail ; then
  set o pipefail
fi
echo $PWD
ls 

FS="/"
JAVAC=${TESTJAVA}${FS}bin${FS}javac
JAVA=${TESTJAVA}${FS}bin${FS}java

$JAVAC -d . $TESTSRC/Main.java 
rm -rf out
$JAVA Main 2>&1 | tee out
r=0
# should pass with broken host and different certificate; fail only on correct host with invalid certificate
cat out | sed '/^[[:space:]]*$/d'  | grep  -v ".*Your client successfully connected to the site. That's bad.*" || r=$?
exit $r
 

