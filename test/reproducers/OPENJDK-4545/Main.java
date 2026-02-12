/* @test
   @bug 6664545
   @summary  nssadapter should not use a single PKCS #11 session for multi-thread operations
   @requires jdk.version.major > 20 & var.msys2.enabled == "false"

   @run shell Main.sh
*/
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class Main {
    private static final int PARALLELISM = 10;
    private static final String ALGORITHM = "AES";
    private static final SecretKeySpec KEY_SPEC = new SecretKeySpec(
            "12345678901234567890123456789012".getBytes(), ALGORITHM);

    private static void importSecretKey() {
        try {
            Cipher c = Cipher.getInstance(ALGORITHM);
            c.init(Cipher.ENCRYPT_MODE, KEY_SPEC);
        } catch (Throwable t) {
            t.printStackTrace();
            System.exit(1);
        }
    }

    private static void exportSecretKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
            kg.generateKey().getEncoded();
        } catch (Throwable t) {
            t.printStackTrace();
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        try (ExecutorService pool = Executors.newFixedThreadPool(PARALLELISM)) {
            for (int t = 0; t < PARALLELISM * 100; t++) {
                pool.submit(Main::importSecretKey);
                pool.submit(Main::exportSecretKey);
            }
        }
    }
}
