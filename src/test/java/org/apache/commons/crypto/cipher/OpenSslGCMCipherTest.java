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
            Assert.assertTrue (true);
        } catch (NoSuchAlgorithmException e) {
            Assert.fail ("AES/GCM/NoPadding Not Supported");
            throw e;
        }
    }
}
