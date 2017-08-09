package org.apache.commons.crypto.cipher;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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

    @Test
    public void testEncrypt () throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, ShortBufferException, IllegalBlockSizeException {
        OpenSsl enc = OpenSsl.getInstance("AES/GCM/NoPadding");

        OpenSsl dec = OpenSsl.getInstance ("AES/GCM/NoPadding");

        KeyGenerator keyGenerator = KeyGenerator.getInstance ("AES");
        keyGenerator.init (256);
        SecretKey key = keyGenerator.generateKey ();

        byte[] nonce = new byte[12];

        SecureRandom secureRandom = new SecureRandom ();

        secureRandom.nextBytes (nonce);

        GCMParameterSpec gcmParameters = new GCMParameterSpec (96, nonce);

        enc.init (OpenSsl.ENCRYPT_MODE, key.getEncoded (), gcmParameters);

        dec.init (OpenSsl.DECRYPT_MODE, key.getEncoded (), gcmParameters);

        byte[] plainText = "covfefe".getBytes (StandardCharsets.UTF_8);

        byte[] cipherText = new byte[plainText.length + 12];

        enc.doFinal (plainText, 0, plainText.length, cipherText, 0);

        byte[] decryptedText = new byte[plainText.length];

        dec.doFinal (cipherText, 0, cipherText.length, decryptedText, decryptedText.length);

        Assert.assertArrayEquals (plainText, decryptedText);


    }
}
