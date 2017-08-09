package org.apache.commons.crypto.cipher;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;

public class OpenSslGCMCipherTest {

    @Test
    public void testValidAlgorithm() throws Exception {
        Assume.assumeTrue(OpenSsl.getLoadingFailureReason() == null);

        try {
            OpenSsl.getInstance("AES/GCM/NoPadding");
            Assert.fail("Should specify correct algorithm.");
        } catch (NoSuchAlgorithmException e) {
            Assert.assertTrue(e.getMessage().contains(
                    "Doesn't support algorithm: AES2 and mode: GCM"));
            throw e;
        }
    }
}
