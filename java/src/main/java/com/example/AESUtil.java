package com.example;

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

    private static final String AES_ALGORITHM = "AES";
    /**
     * 编码
     */
    private static final String CHAR_ENCODING = "UTF-8";


    //************************************提供方便调用的一些方法****************************************

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
     * @param content  要加密的数据
     * @param password 加密密钥
     * @return BASE64编码
     */
    public static String encryptToString(String content, String password) {
        String encrypt = null;
        final byte[] encryptBytes = encrypt(content, password);
        if (encryptBytes != null) {
            encrypt = encode(encryptBytes);
        }
        return encrypt;
    }

    /**
     * 解密
     *
     * @param content  待解密内容(BASE64编码)
     * @param password 解密密钥
     * @return
     */
    public static String decryptByString(String content, String password) {
        String data = null;
        try {
            final byte[] contentBytes = decode(content);
            final byte[] dataBytes = decrypt(contentBytes, password);
            data = new String(dataBytes, CHAR_ENCODING);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return data;
    }
    //**************************************提供一些基础操作********************************************

    /**
     * 加密
     *
     * @param content  需要加密的内容
     * @param password 加密密码
     * @return
     */
    public static byte[] encrypt(String content, String password) {
        byte[] result = null;
        try {
            byte[] byteContent = content.getBytes(CHAR_ENCODING);

            SecretKeySpec key = new SecretKeySpec(getRawKey(password), "AES");

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);// 创建密码器
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
     * @param password 解密密钥
     * @return
     */
    public static byte[] decrypt(byte[] content, String password) {
        byte[] result = null;
        try {
            SecretKeySpec key = new SecretKeySpec(getRawKey(password), "AES");

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);// 创建密码器
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
            result = cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result; // 解密
    }

    private static byte[] getRawKey(String password) throws Exception {
        byte[] seed = password.getBytes(CHAR_ENCODING);
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(seed);

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128, secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }
}
