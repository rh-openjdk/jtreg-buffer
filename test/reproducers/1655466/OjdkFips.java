/**
 * @test
 * @bug 1655466
 * @summary test FIPS providers
 * @author zzambers
 * @requires jdk.version.major >= 8
 * @run main/othervm OjdkFips
 */

import java.util.Set;
import java.util.HashSet;
import java.security.*;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.List;

public class OjdkFips {

    static boolean fipsEnabled() throws Exception {
        Path p = Paths.get("/proc/sys/crypto/fips_enabled");
        if (!Files.exists(p)) {
            return false;
        }
        List lines = Files.readAllLines(p);
        if (lines == null || lines.size() == 0 || ! lines.get(0).equals("1")) {
            return false;
        }
        return true;
    }

    static boolean testJSSEisFIPS(Provider p) throws Exception {
        try {
            Method m = p.getClass().getDeclaredMethod("isFIPS");
            m.setAccessible(true);
            return (Boolean) m.invoke(p);
        } catch (NoSuchMethodException e) {
            // skip this check if method does not exist, was removed in jdk 13:
            // https://bugs.openjdk.java.net/browse/JDK-8217835
            return true;
        }
    }

    static boolean rhFIPSJDK() {
        String otoolProjectName = System.getenv("OTOOL_PROJECT_NAME");
        if (otoolProjectName != null) {
            String[] fipsProjects = { "rpms", "portable", "fips"};
            for (String fipsProject : fipsProjects) {
                if (otoolProjectName.indexOf(fipsProject) >= 0) {
                    return true;
                }
            }
        }
        String vendor = System.getProperty("java.vendor");
        System.out.println(vendor);
        if (vendor.toLowerCase().matches(".*red.*hat.*")) {
            return true;
        }
        return false;
    }

    static boolean testProviders() throws Exception  {
        boolean failed = false;

        // these must be always present
        Set<String> expectedProviders = new HashSet<String>();
        expectedProviders.add("SunPKCS11-NSS-FIPS");
        expectedProviders.add("SUN");
        expectedProviders.add("SunEC");
        expectedProviders.add("SunJSSE");

        // additional providers added to jdk 17 in rhel-8.6
        // http://pkgs.devel.redhat.com/cgit/rpms/java-17-openjdk/commit/?h=rhel-8.6.0&id=eb4e206241b838cb5b174790365b05b83848aebd
        Set<String> expectedProviders2 = new HashSet<String>();
        expectedProviders2.add("SunJCE");
        expectedProviders2.add("SunRsaSign");
        expectedProviders2.add("XMLDSig");

        for (Provider p: Security.getProviders()) {
            String name = p.getName();
            if (name.equals("SunPKCS11-FIPS")) {
                // on jdk 25+ name changed SunPKCS11-NSS-FIPS -> SunPKCS11-FIPS
                name = "SunPKCS11-NSS-FIPS";
            }
            if (! expectedProviders.remove(name)) {
                if (! expectedProviders2.remove(name)) {
                    System.err.println("ERR: unexpected provider: " + name);
                    failed = true;
                }
            }
            if (name.equals("SunJSSE")) {
                if (!testJSSEisFIPS(p)) {
                    System.err.println("ERR: SunJSSE is not FIPS enabled!");
                    failed = true;
                }
            }
        }

        for (String name : expectedProviders) {
            System.err.println("ERR: missing provieder: " + name);
            failed = true;
        }
        return failed;
    }

    public static void main(String[] args) throws Exception {
        if (!fipsEnabled()) {
            System.err.println("FIPS not enabled, skipping!");
            return;
        }
        if (!rhFIPSJDK()) {
            System.err.println("Not RH fips-enabled JDK, skipping!");
            return;
        }
        if (testProviders()) {
            throw new Exception("Test failed");
        }
    }
}
