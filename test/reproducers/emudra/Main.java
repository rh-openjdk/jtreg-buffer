/* @test
   @bug 6896242
   @summary  eMudra certifikate was abolished
   @run shell Main.sh
*/

import java.nio.charset.StandardCharsets;
import java.net.*;
import java.util.*;

public final class Main {
 
    public static void main(String[] args) throws Exception {
       System.out.println(new String(URI.create("https://dv-g3b-emudhra.we-have-a-problem.com/").toURL().openStream().readAllBytes(), StandardCharsets.UTF_8));
    }
}
