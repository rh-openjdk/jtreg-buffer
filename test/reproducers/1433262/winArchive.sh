##
## @test winArchive.sh
## @bug 1433262
## @summary windows archive of input >4gb fails
## @ignore the 8192m.windows.zip have nothing to do with original 8192m.zip issue (which is going to be fixed), but this is not going to be fixed

set -ex

FS="/"
JAVAC=${TESTJAVA}${FS}bin${FS}javac
JAVA=${TESTJAVA}${FS}bin${FS}java

$JAVAC -d . $TESTSRC/TestZip.java
RESOURCE=8192m.windows.zip
$JAVA  TestZip  $TESTSRC/$RESOURCE

