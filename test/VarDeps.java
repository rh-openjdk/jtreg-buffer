import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.Callable;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;



public class VarDeps implements Callable<Map<String, String>> {

    boolean checkVar(String var) {
        String varval = System.getenv(var);
        if (varval == null) { return false; }
        return varval.equalsIgnoreCase("true");
    }

    @Override
    public Map<String, String> call() {
        Map<String, String> map = new HashMap<String, String>();
        map.put("var.rh.jdk", checkVar("RH_JDK") ? "true": "false");
        map.put("var.msys2.enabled", checkVar("MSYS2_ENABLED") ? "true": "false");
        map.put("var.sys.fips", isFipsEnabled() ? "true" : "false");
        map.put("var.os.version.major", String.valueOf(getOsVersionId()));
        return map;
    }

    public static void main(String[] args) {
        for (Map.Entry<String,String> entry: new VarDeps().call().entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }

    private static boolean isFipsEnabled() {
        File flag = new File("/proc/sys/crypto/fips_enabled");
        if (!flag.exists()) {
            return false;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(flag))){
            String value = br.readLine();
            if (value != null) {
                value = value.trim();
                return "1".equals(value);
            }
        } catch (IOException e) {
            // Could not read flag — assume non-FIPS
        }
        return false;
    }

    public static int getOsVersionId() {
        File osRelease = new File("/etc/os-release");
        if (!osRelease.exists()) {
            return -1;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(osRelease))){
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("VERSION_ID=")) {
                    String value = line.split("=", 2)[1].replace("\"", "").trim();
                    String[] parts = value.split("\\.");
                    try {
                        return Integer.parseInt(parts[0]);
                    } catch (NumberFormatException e) {
                        return -1;
                    }
                }
            }
        } catch (IOException e) {
            return -1;
        }
        return -1;
    }
    
}

