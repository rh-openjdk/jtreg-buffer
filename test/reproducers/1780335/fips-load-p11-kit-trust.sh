#!/bin/sh
#
# @test
# @author zzambers
# @bug 1780335
# @requires jdk.version.major >= 8 & jdk.version.major < 25 & var.msys2.enabled == "false"
# @summary FIPS mode Provider refuses to load pk11-kit-trust
# @run shell fips-load-p11-kit-trust.sh
#

set -eux

# skip if not running in fips mode
if ! [ -e /proc/sys/crypto/fips_enabled ] || [ 0 = "$( cat /proc/sys/crypto/fips_enabled )" ] ; then
    printf '%s\n' "not in FIPS mode skipping!" 1>&2
    exit 0
fi

cleanup() {
    if [ -n "${tmpDir:-}" ] ; then
        rm -rf "${tmpDir}"
    fi
}

trap cleanup EXIT

tmpDir="$( mktemp -d )"
nssDir="${tmpDir}/nssdb"

# find config files
securityConfDirOld="${TESTJAVA}/jre/lib/security"
securityConfDirNew="${TESTJAVA}/conf/security"

if [ -d "${securityConfDirNew}" ] ; then
    securityConfDir="${securityConfDirNew}"
elif [ -d "${securityConfDirOld}" ] ; then
    securityConfDir="${securityConfDirOld}"
else
    printf '%s\n' "security conf dir not found!" 1>&2
    exit 1
fi

nssFipsCfgOrig="${securityConfDir}/nss.fips.cfg"
javaSecurityCfgOrg="${securityConfDir}/java.security"
nssFipsCfg="${tmpDir}/nss.fips.cfg"
javaSecurityCfg="${tmpDir}/java.security"

# copy and modify config files
cp "${javaSecurityCfgOrg}" "${javaSecurityCfg}"
cp "${nssFipsCfgOrig}" "${nssFipsCfg}"

fipsProviderPattern1='^fips.provider.1=SunPKCS11.*$'
fipsProviderPattern2='^fips.provider.1=sun.security.pkcs11.SunPKCS11.*$'

if cat "${javaSecurityCfg}" | grep -q "${fipsProviderPattern1}" ; then
    sed -i "s;${fipsProviderPattern1};fips.provider.1=SunPKCS11 ${nssFipsCfg};g" "${javaSecurityCfg}"
elif cat "${javaSecurityCfg}" | grep -q "${fipsProviderPattern2}" ; then
    sed -i "s;${fipsProviderPattern2};fips.provider.1=sun.security.pkcs11.SunPKCS11 ${nssFipsCfg};g" "${javaSecurityCfg}"
else
    printf '%s\n' "SunPKCS11 fips provider not found in java.security!" 1>&2
    exit 1
fi

# find required p11 lib
nssDbDirPattern='^nssSecmodDirectory.*$'
if cat "${nssFipsCfg}" | grep -q "${nssDbDirPattern}" ; then
sed -i "s;${nssDbDirPattern};nssSecmodDirectory = ${nssDir};g" "${nssFipsCfg}"
else
printf '%s\n' "nssSecmodDirectory = ${nssDir}" >> "${nssFipsCfg}"
fi

libfilelib64="/usr/lib64/pkcs11/p11-kit-trust.so"
libfilelib="/usr/lib/pkcs11/p11-kit-trust.so"

if [ -f "${libfilelib64}" ] ; then
    libfile="${libfilelib64}"
elif [ -f "${libfilelib}" ] ; then
    libfile="${libfilelib}"
else
    printf '%s\n' "p11-kit-trust.so not found!" 1>&2
    exit 1
fi

# prepare nssdb
pass=""
mkdir "${nssDir}"
echo "${pass}" > "${nssDir}/password.txt"
certutil -N -d "${nssDir}" -f "${nssDir}/password.txt"
printf '%s:\n' 'Modules original'
modutil -dbdir "${nssDir}" -list
printf '\n' | modutil -dbdir "${nssDir}" -add p11-kit-trust -libfile "${libfile}" -force
printf '%s:\n' 'Modules updated'
modutil -dbdir "${nssDir}" -list
touch "${nssDir}/secmod.db" # workaround for rhbz#1760437

# compile and run test
cp "${TESTSRC}/Main.java" .
"${COMPILEJAVA}/bin/javac" Main.java
"${TESTJAVA}/bin/java" -Djava.security.properties=="${javaSecurityCfg}" Main "${pass}"
