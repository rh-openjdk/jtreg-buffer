import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.Callable;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

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
        Path flag = Path.of("/proc/sys/crypto/fips_enabled");
        try {
            if (Files.exists(flag)) {
                String value = Files.readString(flag).trim();
                return "1".equals(value);
            }
        } catch (IOException e) {
            // Could not read flag — assume non-FIPS
        }
        return false;
    }

    public static int getOsVersionId() {
        Path osRelease = Path.of("/etc/os-release");
        if (!Files.exists(osRelease)) {
            return -1;
        }

        try {
            List<String> lines = Files.readAllLines(osRelease);
            for (String line : lines) {
                if (line.startsWith("VERSION_ID=")) {
                    String value = line.split("=", 2)[1].replaceAll("\"", "").trim();
                    // Extract leading integer part (e.g. "10.0" → 10)
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
