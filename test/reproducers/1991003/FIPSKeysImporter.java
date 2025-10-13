/*
 * Copyright (c) 2021, Red Hat, Inc.
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;

/*
 * @test
 * @summary Test for RH1991003 - FIPS keys importer
 * @requires var.sys.fips == "true" & ( !(os.version ~= ".*el.*") | var.os.version.major >= 10 ) 
 * @run main/othervm/timeout=30 FIPSKeysImporter
 */

public class FIPSKeysImporter {

    protected static final boolean enableDebug = true;

    protected static final String knownText =
            "Known text known text known text";

    protected static final byte[] secretKey = new byte[32];

    protected static final int PLAIN_ORIGIN = 1;
    protected static final int JKS_ORIGIN = 2;

    protected static final List<String[]> rootCAs = new ArrayList<>();
    static {
        rootCAs.add(new String[] {"root_ca_1", "RSA"});
        rootCAs.add(new String[] {"root_ca_2", "EC"});
    }

    protected static List<String[]> KSs = new ArrayList<>();
    static {
        KSs.add(new String[] {"JKS", "jks"});
    }

    protected static char[] passphrase = "123456".toCharArray();

    protected Map<String, KeyStore> kss = new HashMap<>();
    protected Map<String, TestCA> cas = new HashMap<>();

    protected static class TestCA {

        protected String alias;
        protected Map<Integer, Certificate> certs = new HashMap<>();
        protected Map<Integer, PrivateKey> privKeys = new HashMap<>();
        protected Map<Integer, PublicKey> pubKeys = new HashMap<>();

        TestCA(String alias) {
            this.alias = alias;
        }

        Certificate getCertificate(int origin) {
            return certs.get(origin);
        }

        PublicKey getPublicKey(int origin) {
            return pubKeys.get(origin);
        }

        PrivateKey getPrivateKey(int origin) {
            return privKeys.get(origin);
        }

        void addCertificate(int origin, Certificate cert) {
            certs.put(origin, cert);
        }

        void addPublicKey(int origin, PublicKey pubKey) {
            pubKeys.put(origin, pubKey);
        }

        void addPrivateKey(int origin, PrivateKey privKey) {
            privKeys.put(origin, privKey);
        }
    }

    public static void main(String[] args) throws Throwable {
        FIPSKeysImporter fki = new FIPSKeysImporter();
        fki.loadKSS();
        fki.loadCAS();
        fki.testSignature();
        fki.testCipher();
        fki.testTLS();
        System.out.println("TEST PASS - OK");
    }

    protected void testTLS() throws Throwable {
        TLSTester.doTestTLS(kss.get("JKS"));
    }

    protected void testSignature() throws Throwable {
        TestCA rootCA1 = cas.get("root_ca_1");
        doTestSignature("SHA256WithRSA", rootCA1.getPrivateKey(PLAIN_ORIGIN),
                rootCA1.getPublicKey(PLAIN_ORIGIN));
        doTestSignature("SHA256WithRSA", rootCA1.getPrivateKey(JKS_ORIGIN),
                rootCA1.getPublicKey(JKS_ORIGIN));

        TestCA rootCA2 = cas.get("root_ca_2");
        doTestSignature("SHA256WithECDSA", rootCA2.getPrivateKey(PLAIN_ORIGIN),
                rootCA2.getPublicKey(PLAIN_ORIGIN));
        doTestSignature("SHA256WithECDSA", rootCA2.getPrivateKey(JKS_ORIGIN),
                rootCA2.getPublicKey(JKS_ORIGIN));
    }

    protected void testCipher() throws Throwable {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        if (enableDebug) {
            System.out.println("Cipher Provider: " + c.getProvider());
        }
        IvParameterSpec ivPar = new IvParameterSpec(new byte[16]);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey, "AES"),
                ivPar);
        byte[] cipherText = c.doFinal(knownText.getBytes());
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretKey, "AES"),
                ivPar);
        byte[] plainText = c.doFinal(cipherText);
        if (!Arrays.equals(knownText.getBytes(), plainText)) {
            throw new Exception("Decrypted text is not equal to the original");
        }
        if (enableDebug) {
            System.out.println("Cipher test successful");
        }
    }

    protected static void doTestSignature(String sigAlg, PrivateKey privKey,
            PublicKey pubKey) throws Throwable {
        byte[] knownTextSig = null;
        Signature s = Signature.getInstance(sigAlg);
        if (enableDebug) {
            System.out.println("Signature algorithm: " + sigAlg);
            System.out.println("Signature Provider: " + s.getProvider());
            System.out.println("Private key for signature: " + privKey);
            System.out.println("Public key for signature: " + pubKey);
        }
        s.initSign(privKey);
        s.update(knownText.getBytes());
        knownTextSig = s.sign();
        s.initVerify(pubKey);
        s.update(knownText.getBytes());
        if (s.verify(knownTextSig) == false) {
            throw new Exception("Could not verify signature");
        }
        if (enableDebug) {
            System.out.println("Signature verified");
        }
    }

    protected void loadKSS() throws Throwable {
        for (String[] ks : KSs) {
            kss.put(ks[0], readKeyStore(ks[0], ks[1]));
        }
    }

    protected static KeyStore readKeyStore(String keystoreType, String fileExtension)
            throws Exception {
        File file = new File(System.getProperty("test.src", "."),
                "keystore." + fileExtension);
        InputStream in = new FileInputStream(file);
        KeyStore ks = KeyStore.getInstance(keystoreType);
        ks.load(in, passphrase);
        in.close();
        return ks;
    }

    protected void loadCAS() throws Throwable {
        for (String[] rootCA : rootCAs) {
            loadPlainCA(rootCA[0], rootCA[1]);
            loadJKSCA(rootCA[0], rootCA[1]);
        }
    }

    protected TestCA getCA(String alias) {
        TestCA ca = cas.get(alias);
        if (ca == null) {
            ca = new TestCA(alias);
            cas.put(alias, ca);
        }
        return ca;
    }

    protected void loadPlainCA(String alias, String alg) throws Throwable {
        TestCA ca = getCA(alias);
        Certificate cert = readCertificate(alias);
        ca.addCertificate(PLAIN_ORIGIN, cert);
        ca.addPublicKey(PLAIN_ORIGIN, cert.getPublicKey());
        ca.addPrivateKey(PLAIN_ORIGIN, readPrivateKey(alias, alg));
    }

    protected void loadJKSCA(String alias, String alg) throws Throwable {
        KeyStore ks = kss.get("JKS");
        TestCA ca = getCA(alias);
        Certificate cert = ks.getCertificate(alias);
        ca.addCertificate(JKS_ORIGIN, cert);
        ca.addPublicKey(JKS_ORIGIN, cert.getPublicKey());
        ca.addPrivateKey(JKS_ORIGIN, (PrivateKey)ks.getKey(alias, passphrase));
    }

    protected static PrivateKey readPrivateKey(String alias, String alg) throws Throwable {
        byte[] privKeyBytes = readAllFileBytes(alias + "_private_key_bytes");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privKeyBytes);
        KeyFactory kf = KeyFactory.getInstance(alg);
        return kf.generatePrivate(spec);
    }

    protected static Certificate readCertificate(String alias) throws Throwable {
        byte[] certificateBytes = readAllFileBytes(alias + "_certificate.pem");
        return CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(
                        certificateBytes));
    }

    protected static byte[] readAllFileBytes(String fileName) throws IOException {
        Path p = Paths.get(System.getProperty("test.src", "."), fileName);
        return Files.readAllBytes(p);
    }

    protected static class TLSTester {
        public static void doTestTLS(KeyStore ks) throws Throwable {
            SSLEngine[][] enginesToTest = getSSLEnginesToTest(ks);

            for (SSLEngine[] engineToTest : enginesToTest) {
                SSLEngine clientSSLEngine = engineToTest[0];
                SSLEngine serverSSLEngine = engineToTest[1];

                // SSLEngine code based on RedhandshakeFinished.java
                boolean dataDone = false;
                ByteBuffer clientOut = null;
                ByteBuffer clientIn = null;
                ByteBuffer serverOut = null;
                ByteBuffer serverIn = null;
                ByteBuffer cTOs;
                ByteBuffer sTOc;

                SSLSession session = clientSSLEngine.getSession();
                int appBufferMax = session.getApplicationBufferSize();
                int netBufferMax = session.getPacketBufferSize();

                clientIn = ByteBuffer.allocate(appBufferMax + 50);
                serverIn = ByteBuffer.allocate(appBufferMax + 50);

                cTOs = ByteBuffer.allocateDirect(netBufferMax);
                sTOc = ByteBuffer.allocateDirect(netBufferMax);

                clientOut = ByteBuffer.wrap(
                        "Hi Server, I'm Client".getBytes());
                serverOut = ByteBuffer.wrap(
                        "Hello Client, I'm Server".getBytes());

                SSLEngineResult clientResult;
                SSLEngineResult serverResult;

                while (!dataDone) {
                    clientResult = clientSSLEngine.wrap(clientOut, cTOs);
                    runDelegatedTasks(clientResult, clientSSLEngine);
                    serverResult = serverSSLEngine.wrap(serverOut, sTOc);
                    runDelegatedTasks(serverResult, serverSSLEngine);
                    cTOs.flip();
                    sTOc.flip();

                    if (enableDebug) {
                        System.out.println("Client -> Network");
                        printTlsNetworkPacket("", cTOs);
                        System.out.println("");
                        System.out.println("Server -> Network");
                        printTlsNetworkPacket("", sTOc);
                        System.out.println("");
                    }

                    clientResult = clientSSLEngine.unwrap(sTOc, clientIn);
                    runDelegatedTasks(clientResult, clientSSLEngine);
                    serverResult = serverSSLEngine.unwrap(cTOs, serverIn);
                    runDelegatedTasks(serverResult, serverSSLEngine);

                    cTOs.compact();
                    sTOc.compact();

                    if (!dataDone &&
                            (clientOut.limit() == serverIn.position()) &&
                            (serverOut.limit() == clientIn.position())) {
                        checkTransfer(serverOut, clientIn);
                        checkTransfer(clientOut, serverIn);
                        dataDone = true;
                    }
                }
            }
        }

        static void printTlsNetworkPacket(String prefix, ByteBuffer bb) {
            ByteBuffer slice = bb.slice();
            byte[] buffer = new byte[slice.remaining()];
            slice.get(buffer);
            for (int i = 0; i < buffer.length; i++) {
                System.out.printf("%02X, ", (byte)(buffer[i] & (byte)0xFF));
                if ((i + 1) % 8 == 0 && (i + 1) % 16 != 0) {
                    System.out.print(" ");
                }
                if ((i + 1) % 16 == 0) {
                    System.out.println("");
                }
            }
            if (buffer.length > 0) {
                System.out.println("");
            }
            System.out.flush();
        }

        protected static void checkTransfer(ByteBuffer a, ByteBuffer b)
                throws Throwable {
            a.flip();
            b.flip();
            if (!a.equals(b)) {
                throw new Exception("Data didn't transfer cleanly");
            }
            a.position(a.limit());
            b.position(b.limit());
            a.limit(a.capacity());
            b.limit(b.capacity());
        }

        protected static void runDelegatedTasks(SSLEngineResult result,
                SSLEngine engine) throws Throwable {

            if (result.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
                Runnable runnable;
                while ((runnable = engine.getDelegatedTask()) != null) {
                    runnable.run();
                }
                HandshakeStatus hsStatus = engine.getHandshakeStatus();
                if (hsStatus == HandshakeStatus.NEED_TASK) {
                    throw new Exception(
                        "handshake shouldn't need additional tasks");
                }
            }
        }

        protected static SSLEngine[][] getSSLEnginesToTest(KeyStore ks)
                throws Throwable {
            SSLEngine[][] enginesToTest = new SSLEngine[1][2];
            String[][] preferredSuites = new String[][]{ new String[] {
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            }};
            for (int i = 0; i < enginesToTest.length; i++) {
                enginesToTest[i][0] = createSSLEngine(ks, true);
                enginesToTest[i][1] = createSSLEngine(ks, false);
                enginesToTest[i][0].setEnabledCipherSuites(preferredSuites[i]);
                enginesToTest[i][1].setEnabledCipherSuites(preferredSuites[i]);
            }
            return enginesToTest;
        }

        protected static SSLEngine createSSLEngine(KeyStore ks, boolean client)
                throws Throwable {
            SSLEngine ssle;
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
            kmf.init(ks, passphrase);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(ks);

            SSLContext sslCtx = SSLContext.getInstance("TLSv1.2");
            sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            ssle = sslCtx.createSSLEngine("localhost", 443);
            ssle.setUseClientMode(client);
            SSLParameters sslParameters = ssle.getSSLParameters();
            ssle.setSSLParameters(sslParameters);

            return ssle;
        }
    }
}
