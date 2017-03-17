package com.blingbling.rsademo;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by BlingBling on 2017/3/17.
 */

public class AESUtil {
    private AESUtil() {}

    public static final String SECRETKEYSPEC_ALGORITHM = "AES";
    public static final String SECURERANDOM_SHA1 = "SHA1PRNG";
    public static final String SECURERANDOM_CRYPTO = "Crypto";
    public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
    /**
     * 编码
     */
    private static final String CHAR_ENCODING = "UTF-8";


    //************************************提供方便调用的一些方法****************************************

    public static String initKeyToString(String password) {
        String key = null;
        try {
            key = encode(initKey(password));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return key;
    }

    /**
     * Base64编码数据
     *
     * @param binaryData
     * @return
     */
    public static String encode(byte[] binaryData) {
        return Base64Util.encode(binaryData);
    }

    /**
     * Base64解码数据
     *
     * @param encoded (BASE64编码)
     * @return
     */
    public static byte[] decode(String encoded) {
        return Base64Util.decode(encoded);
    }


    /**
     * 加密
     *
     * @param content 要加密的数据
     * @param key     加密密钥(BASE64编码)
     * @return BASE64编码
     */
    public static String encrypt(String content, String key) {
        String encrypt = null;
        final byte[] keyBytes = decode(key);
        final byte[] encryptBytes = encrypt(content, keyBytes);
        if (encryptBytes != null) {
            encrypt = encode(encryptBytes);
        }
        return encrypt;
    }

    /**
     * 解密
     *
     * @param content 待解密内容(BASE64编码)
     * @param key     解密密钥(BASE64编码)
     * @return
     */
    public static String decrypt(String content, String key) {
        String data = null;
        try {
            final byte[] contentBytes = decode(content);
            final byte[] keyBytes = decode(key);
            final byte[] dataBytes = decrypt(contentBytes, keyBytes);
            data = new String(dataBytes, CHAR_ENCODING);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return data;
    }
    //**************************************提供一些基础操作********************************************

    /**
     * 生成加密的Key
     *
     * @param password
     * @return
     * @throws Exception
     */
    public static byte[] initKey(String password) throws Exception {
        SecureRandom secureRandom = SecureRandom.getInstance(SECURERANDOM_SHA1, SECURERANDOM_CRYPTO);
        secureRandom.setSeed(password.getBytes());

        KeyGenerator keyGenerator = KeyGenerator.getInstance(SECRETKEYSPEC_ALGORITHM);
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * 加密
     *
     * @param content  需要加密的内容
     * @param keyBytes 加密密码
     * @return
     */
    public static byte[] encrypt(String content, byte[] keyBytes) {
        byte[] result = null;
        try {
            byte[] byteContent = content.getBytes(CHAR_ENCODING);

            SecretKeySpec key = new SecretKeySpec(keyBytes, SECRETKEYSPEC_ALGORITHM);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
            result = cipher.doFinal(byteContent);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result; // 加密
    }

    /**
     * 解密
     *
     * @param content  待解密内容
     * @param keyBytes 解密密钥
     * @return
     */
    public static byte[] decrypt(byte[] content, byte[] keyBytes) {
        byte[] result = null;
        try {
            SecretKeySpec key = new SecretKeySpec(keyBytes, SECRETKEYSPEC_ALGORITHM);

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
            result = cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result; // 解密
    }

}
