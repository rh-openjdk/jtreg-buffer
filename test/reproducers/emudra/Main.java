/* @test
   @bug 6896242
   @summary  eMudra certifikate was abolished
   @run shell Main.sh
*/

import java.nio.charset.StandardCharsets;
import java.io.*;
import java.net.*;
import java.util.*;

public final class Main {
 
    public static void main(String[] args) throws Exception {
       System.out.println(new String(readAllBytes(URI.create("https://dv-g3b-emudhra.we-have-a-problem.com/").toURL().openStream()), StandardCharsets.UTF_8));
    }

public static byte[] readAllBytes(InputStream inputStream) throws Exception {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int nRead;
    byte[] data = new byte[16384];
    while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
        buffer.write(data, 0, nRead);
    }
    return buffer.toByteArray();
}

}
