set -exu
echo $PWD
ls 

FS="/"
JAVAC=${TESTJAVA}${FS}bin${FS}javac
JAVA=${TESTJAVA}${FS}bin${FS}java

$JAVAC -d . $TESTSRC/Main.java 
for x in `seq 10` ; do
	$JAVA Main
done


