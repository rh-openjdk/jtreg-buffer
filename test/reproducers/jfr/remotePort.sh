##
## @test 
## @requires jdk.version.major > 10
## @bug 1444666
## @summary check if jfr can be started in runtime via vmattach

set -exo pipefail

if [ ! "x${TESTJAVA}" == "x" ] ; then
  FS="/"
  JAVAC=${TESTJAVA}${FS}bin${FS}javac
  JAVA=${TESTJAVA}${FS}bin${FS}java
  JFR=${TESTJAVA}${FS}bin${FS}jfr
else
  JAVAC=$(readlink -f `which javac`)
  JAVA=$(readlink -f `which java`)
  JFR=$(readlink -f `which jfr`)
fi

if [ "x${TESTSRC}" == "x" ] ; then
  TESTSRC=`pwd`
fi

#hardcoded in ClientCmdLike.java
FLIGHTFILE=remotePortFlight.jfr
PORT=64686
${JAVAC} -d . $TESTSRC/Server.java
${JAVAC} -d . $TESTSRC/JmxClientPort.java
${JAVA} Server  8 &
sleep 1
JMX_ARGS="-Dcom.sun.management.jmxremote  -Dcom.sun.management.jmxremote.authenticate=false  -Dcom.sun.management.jmxremote.ssl=false -Dcom.sun.management.jmxremote.port=$PORT -Djava.rmi.server.hostname=localhost"
${JAVA} $JMX_ARGS JmxClientPort  $PORT
sleep 4
${JFR} print  $FLIGHTFILE | (head; tail)
parsedLines=`cat $FLIGHTFILE | wc -l`
test $parsedLines -gt 1000
rm $FLIGHTFILE 
