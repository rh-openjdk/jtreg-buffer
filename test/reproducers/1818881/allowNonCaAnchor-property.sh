#!/bin/bash

# @test jdk.security.allowNonCaAnchor-property
# @requires (var.rh.jdk == "true") & (jdk.version.major > 8 | !(vm.debug == "true" & hydra.using.jfron == "true"))
# @bug 1818881
# @summary security property jdk.security.allowNonCaAnchor works
# @run shell allowNonCaAnchor-property.sh

function findFreePort() {
  local BASE_PORT=9999
  local INCREMENT=1
  local port=$BASE_PORT

  while netstat ${NETSTAT_ARGS:--taln} | grep -q ":$port " ; do
      port=$((port+INCREMENT))
  done
  echo "found $port" >&2
  echo $port
}

if [ "x$OTOOL_cryptosetup" == "xfips" -o "x`update-crypto-policies --show`" == "xFIPS"  ] ; then
  echo "fips detected, skipping 1818881 allowNonCaAnchor-property"
  exit 0
else
  echo "probably non-fips environment"
fi

if [ "${TESTSRC}" = "" ] ; then
  TESTSRC=.
fi

if [ "${TESTJAVA}" = "" ] ; then
  PATH_JAVA=$(readlink -f $(which javac))
  TESTJAVA=$(dirname $(dirname ${PATH_JAVA}))
  echo "TESTJAVA not set, selecting " ${TESTJAVA}
  echo "If this is incorrect, try setting the variable manually."
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
    # netstat on windows has different switches
    NETSTAT_ARGS="-an"
    ;;
  * )
    echo "Unrecognized system!"
    exit 1;
    ;;
esac

set -exo pipefail

SERVER_STORE=jboss.server.keystore.jks
CLIENT_STORE=jboss.client.keystore.jks
CACERT=ca.cer

garbage="$CACERT
ca.jks
clientLog1
clientLog2
HTTPSClient\$1.class
HTTPSClient.class
HTTPSServer\$ServerThread.class
HTTPSServer.class
jboss.cer
jboss.csr
$CLIENT_STORE
$SERVER_STORE
serverLog"
function clean() {
  if [ "x$CLEAN" == "xtrue" ] ; then
    rm -fv $garbage
  fi
}
trap clean EXIT # will be overwritten later if server starts

$TESTJAVA/bin/javac -d . $TESTSRC/HTTPSClient.java
$TESTJAVA/bin/javac -d . $TESTSRC/HTTPSServer.java

if [ "x$CLEAN" == "x" ] ; then
  CLEAN="true"
fi
if [ "x$GEN_KEYS" == "x" ] ; then
  GEN_KEYS="true"
fi

CA="false"
EXT="-ext BC=ca:$CA,pathlen:3"

if [ "x$GEN_KEYS" == "xtrue" ] ; then
  $TESTJAVA/bin/keytool -genkeypair -alias ca    -keystore $CLIENT_STORE -storepass secret -keypass secret -dname cn=ca,dc=redhat,dc=com -keysize 2048 -keyalg RSA -validity 365 $EXT
  $TESTJAVA/bin/keytool -exportcert -alias ca    -keystore $CLIENT_STORE -storepass secret -file $CACERT
  $TESTJAVA/bin/keytool -genkeypair -alias jboss -keystore $SERVER_STORE -storepass secret -keypass secret -dname "cn=jboss.usersys.redhat.com, ou=GSS,dc=redhat,dc=com" -keysize 2048 -keyalg RSA $EXT
  $TESTJAVA/bin/keytool -certreq    -alias jboss -keystore $SERVER_STORE -storepass secret -file jboss.csr
  $TESTJAVA/bin/keytool -gencert    -alias ca    -keystore $CLIENT_STORE -storepass secret -keypass secret -infile jboss.csr -outfile jboss.cer -validity 365 $EXT
  $TESTJAVA/bin/keytool -importcert -alias ca    -keystore $SERVER_STORE -storepass secret -trustcacerts -file $CACERT -noprompt
  $TESTJAVA/bin/keytool -importcert -alias jboss -keystore $SERVER_STORE -storepass secret -file jboss.cer -noprompt
fi

$TESTJAVA/bin/keytool  -list  -keystore $SERVER_STORE  -storepass secret  -v | grep -e "CA:" -A 5 -B 5
$TESTJAVA/bin/keytool  -list  -keystore $SERVER_STORE  -storepass secret  -v | grep -e "CA:$CA"

FOUND_PORT=`findFreePort`

SOPTS="-Djavax.net.ssl.keyStore=$SERVER_STORE 
       -Djavax.net.ssl.keyStorePassword=secret 
       -Djavax.net.ssl.trustStore=$SERVER_STORE
       -Djavax.net.ssl.trustStorePassword=secret
       -Djavax.net.ssl.trustStoreType=jks
       -Dtest.port=$FOUND_PORT"
COPTS="-Djavax.net.ssl.trustStore=$CLIENT_STORE
       -Djavax.net.ssl.trustStorePassword=secret
       -Djavax.net.ssl.trustStoreType=jks
       -Dtest.port=$FOUND_PORT"
ANCHOR="-Djdk.security.allowNonCaAnchor"

serverLog=serverLog
rm -f pid
(set -eo pipefail ; $TESTJAVA/bin/java $SOPTS  HTTPSServer 2>&1 & echo $! > pid ) | tee $serverLog &
i=0
while [ "$i" -lt 30 ] ; do
    if [ -f pid ] && grep -q '^[0-9]*$' pid ; then
        break
    fi
    sleep 1
    i=$(( ++i ))
done
SERVER_PID=$(cat pid)
rm -f pid

function killServer() {
  $TESTJAVA/bin/jps
  kill $SERVER_PID
  clean
}
trap killServer EXIT

i=0
while ! cat $serverLog | grep "SSL server started"; do
  if [ $i -gt 30 ] ; then
    echo "server not started"
    exit 1
  fi
  let i=i+1
  sleep 1
done

p1=0;
$TESTJAVA/bin/java $COPTS "$ANCHOR=false" HTTPSClient > clientLog1 2>&1 || p1=$?
p2=0;
$TESTJAVA/bin/java $COPTS "$ANCHOR=true"  HTTPSClient > clientLog2 2>&1 || p2=$?

set +x
echo "with  anchor=false => $p1"
echo "with  anchor=true  => $p2"
set -x
test  $p2 -eq 0
test  $p1 -gt 0
cat clientLog2 | grep "RETURN : 200"
cat clientLog1 | grep "RETURN : 200" && exit 1
cat clientLog2 | grep "SSLHandshakeException" && exit 1
cat clientLog1 | grep "SSLHandshakeException"
set +x
echo "if nto failed until now, PASSED"
echo "will kill server now and clean if allowed($CLEAN)"
set -x

