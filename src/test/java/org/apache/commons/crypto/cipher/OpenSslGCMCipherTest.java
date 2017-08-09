package org.apache.commons.crypto.cipher;

import org.apache.commons.crypto.utils.Utils;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;

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
    public void testEncrypt () throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, ShortBufferException, IllegalBlockSizeException, IOException, InvalidKeyException {

        String transform = "AES/GCM/NoPadding";

        Properties properties = new Properties();
        properties.setProperty(CryptoCipherFactory.CLASSES_KEY, CryptoCipherFactory.CipherProvider.OPENSSL.getClassName());
        CryptoCipher enc = Utils.getCipherInstance(transform, properties);

        CryptoCipher dec = Utils.getCipherInstance (transform, properties);


        KeyGenerator keyGenerator = KeyGenerator.getInstance ("AES");
        keyGenerator.init (256);
        SecretKey key = keyGenerator.generateKey ();

        byte[] nonce = new byte[12];

        SecureRandom secureRandom = new SecureRandom ();

        secureRandom.nextBytes (nonce);

        GCMParameterSpec gcmParameters = new GCMParameterSpec (96, nonce);

        enc.init (Cipher.ENCRYPT_MODE, key, gcmParameters);

        dec.init (Cipher.DECRYPT_MODE, key, gcmParameters);

        byte[] plainText = "covfefe".getBytes (StandardCharsets.UTF_8);

        byte[] tmpText = new byte[plainText.length * 4];

        int updateBytes = enc.update (plainText, 0, plainText.length, tmpText, 0);

        int finalBytes = enc.doFinal (plainText, 0, 0, tmpText, updateBytes);



        enc.close ();


        byte[] decryptedTempText = new byte[32];


        int updateFinalBytes = dec.doFinal (tmpText, 0, updateBytes + finalBytes, decryptedTempText, 0);

        byte[] decryptedText = Arrays.copyOf (decryptedTempText,  updateFinalBytes);

        System.out.println ("Decrypted Text " + new String (decryptedText, StandardCharsets.UTF_8));

	    Assert.assertTrue (decryptedText.length > 0);


    }
}
