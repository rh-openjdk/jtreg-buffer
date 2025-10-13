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

/*
 * @test
 * @summary Test for RH1991003 - FIPS keys importer
 * @requires var.sys.fips == "false" | (os.version ~= ".*el.*" & var.os.version.major < 10)
 * @run main/othervm/timeout=30 FIPSKeysImporterDSA
 */

public final class FIPSKeysImporterDSA extends FIPSKeysImporter {

    static {
        rootCAs.add(new String[] {"root_ca_0", "DSA"});
    }

    public static void main(String[] args) throws Throwable {
        FIPSKeysImporterDSA fki = new FIPSKeysImporterDSA();
        fki.loadKSS();
        fki.loadCAS();
        fki.testSignature();
        fki.testCipher();
        fki.testTLS();
        System.out.println("TEST PASS - OK");
    }

    @Override
    protected void testSignature() throws Throwable {
        super.testSignature();
        TestCA rootCA0 = cas.get("root_ca_0");
        doTestSignature("SHA256withDSA", rootCA0.getPrivateKey(PLAIN_ORIGIN),
                rootCA0.getPublicKey(PLAIN_ORIGIN));

        doTestSignature("SHA256withDSA", rootCA0.getPrivateKey(JKS_ORIGIN),
                rootCA0.getPublicKey(JKS_ORIGIN));
    }
}
