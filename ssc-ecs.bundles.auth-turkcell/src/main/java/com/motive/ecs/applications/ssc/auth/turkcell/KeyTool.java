package com.motive.ecs.applications.ssc.auth.turkcell;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Properties;

public class KeyTool {

	private static final Logger logger = Logger.getLogger(KeyTool.class);

    private static Properties prop;

    public static String decrypt(byte[] cipherText) {

    	logger.info("XXXXXXENTERED");

        PrivateKey privateKey = null;
        try {
            privateKey = getPrivateCrtKeySpec();

            logger.info("ALGORITHM: "+privateKey.getAlgorithm());

            Cipher cipherr = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING");
            cipherr.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decoded = Base64.decodeBase64(cipherText);
            byte[] doFinal = cipherr.doFinal(decoded);
            String returnStr = new String(doFinal, "UTF-8");
            logger.info("[decrypt method] final text=" + returnStr);
            return returnStr;
        } catch (Exception e) {
        	logger.error("[decrypt method] error occurred\nMessage:" + e.getMessage());
        }
        return "";
    }

    private static PrivateKey getPrivateCrtKeySpec() throws Exception {
        BigInteger modulus = new BigInteger(1, Base64.decodeBase64(getProperty("ssc.turkcell.keytool.privateModulus").trim()));
        BigInteger publicExponent = new BigInteger(1, Base64.decodeBase64(getProperty("ssc.turkcell.keytool.privateExponent").trim()));
        BigInteger privateExponent = new BigInteger(1, Base64.decodeBase64(getProperty("ssc.turkcell.keytool.privateD").trim()));
        BigInteger primeP = new BigInteger(1, Base64.decodeBase64(getProperty("ssc.turkcell.keytool.privateP").trim()));
        BigInteger primeQ = new BigInteger(1, Base64.decodeBase64(getProperty("ssc.turkcell.keytool.privateQ").trim()));
        BigInteger primeExponentP = new BigInteger(1, Base64.decodeBase64(getProperty("ssc.turkcell.keytool.privateDP").trim()));
        BigInteger primeExponentQ = new BigInteger(1, Base64.decodeBase64(getProperty("ssc.turkcell.keytool.privateDQ").trim()));
        BigInteger crtCoefficient = new BigInteger(1, Base64.decodeBase64(getProperty("ssc.turkcell.keytool.privateInverseQ").trim()));

        RSAPrivateKeySpec privSpec = new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP, primeQ,
                primeExponentP, primeExponentQ, crtCoefficient);

        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privKey = factory.generatePrivate(privSpec);
        return privKey;
    }

    private static String getProperty(String name) {
        if (prop == null) {
            prop = new Properties();
            InputStream input = null;
            try {

                //input = new FileInputStream("config/KeyTool.properties");
                //input = new FileInputStream("C:/IdeaProjects/ScalaPrograms/denemeMaven/src/main/java/KeyTool/KeyTool.properties");
                input = new FileInputStream("/data01/motive/ecs/apache-servicemix-4.3.0/deploy/KeyTool.properties");
                

                // load a properties file
                prop.load(input);

            } catch (IOException ex) {
            	logger.error("[getProperty method] error occurred during property file loading.\nMessage:" + ex.getMessage());
            } finally {
                if (input != null) {
                    try {
                        input.close();
                    } catch (IOException e) {
                    	logger.error("[getProperty method] could not close the file.\nMessage:" + e.getMessage());

                    }
                }
            }
        }
        return prop.getProperty(name);
    }

    public static boolean validateToken(String encodedTokenStr) {
        try {
            if (encodedTokenStr != null && encodedTokenStr.length() > 0 && encodedTokenStr.indexOf("##") > -1) {
                String[] tokenContent = encodedTokenStr.split("##");
                if ("".equals(getProperty("ssc.turkcell.token.ttl")) || tokenContent.length != 2) return false;

                long ttl = Long.valueOf(getProperty("ssc.turkcell.token.ttl"));
                long now = System.currentTimeMillis();
                long tokenTime = Long.valueOf(tokenContent[1]);
                if (((now - tokenTime) / 1000) < ttl) {
                	logger.info("[validateToken method] token validated");
                    return true;
                }
                logger.info("[validateToken method] token expired");
            }
        } catch (Exception ex) {
        	logger.error("[validateToken method] error occurred\nMessage:" + ex.getMessage());
        }
        return false;
    }

    public static void main(String[] args) {
        try {
            // TODO Auto-generated method stub
            //String cipherText = "FS0u7WIa2JhI3bjrGtYXCpYaWbbh8m6BBXbH28tZ1hEFLg+jNQLVH7n0dZXfhk+k7L8iwCi6iA5psNafyO+1vYIujTYFAc3Fs+XV7J9i04EFgX7R1dXfR176Rxek5aNbTjEfi+w/uNHe2RmxaDhfxSV8ha6UYEluVrW2hBl4vHmilYS9Nqsk6xMaa2qTn37qCYvV38JtG0u2GD49jyWFbTpaReE7I5/xT/abKYIrej3UM+/aQ4r3YRcOGxBH4nZCTR5HRMz6IKilcwWOjy2rLrBq0t9ug2TdD9NzJ6gKpS+oNjlGROXgqMENxVeWHLDnvjEykM8hVJ4bAPDRx4n3Og==";
            String cipherText = "GyKKWHU9jczpx818AltwzQG9FcQPkyQ3cZ/ecPkwm+eHE+rHUd0HeXT77a6WeDb7xCQ4E3Pyx8IzEN73VidGt6tGermsFXfVI8dyFdxoBjux7RangpwVINrc+DbnDig3MFkv8w1WBz4hXLL84g2rXzo1Z67Zsyf1EzF8ru40v525i7sk4AFltpYZNmaDVgCiWs3kSh5+n9n+LpVxvXOa95nsQzA+jtSm95JNPOqwNjAD+yhQGU183EjlNpcKtjptHwsJbnsz9k7P87/ttVDC+TAOMCuz8xUpDK+lF9DbeZMazQgK1xhrf6CDALKPc2n6GkYr3QM9SaSpKhiDfHFhsA==";
            String original = KeyTool.decrypt(cipherText.getBytes());
            validateToken(original);

        } catch (Exception e) {
            System.err.println(e);
        }
    }
}

