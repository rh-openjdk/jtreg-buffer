import java.net.URL;
import java.io.*;
import javax.net.ssl.*;

/*
 * @test
 * @bug 1906862
 * @summary failing on listing policies in default mode
 * @run main CipherList
 */

public class CipherList
{
  public static void main(String[] args)
  throws Exception
  {
    SSLContext context = SSLContext.getDefault();
    int i;
    SSLSocketFactory sf = context.getSocketFactory();
    String[] cipherSuites = sf.getDefaultCipherSuites();

    for (i=0;i<cipherSuites.length;i++)
    {
      System.out.println(cipherSuites[i]);
    }
  }
}

