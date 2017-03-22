package com.example.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by BlingBling on 2017/3/17.
 */

public class AESUtil {
    private AESUtil() {}

    public static final String AES_ALGORITHM = "AES";
    public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
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
    private static String encode(byte[] binaryData) {
        return BASE64Util.encode(binaryData);
    }

    /**
     * Base64解码数据
     *
     * @param encoded (BASE64编码)
     * @return
     */
    private static byte[] decode(String encoded) {
        return BASE64Util.decode(encoded);
    }

    /**
     * 生成加密的Key
     *
     * @return
     */
    public static String initKeyToString() {
        String key = null;
        try {
            key = encode(initKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return key;
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
        try {
            final byte[] keyBytes = decode(key);
            final byte[] encryptBytes = encrypt(content, keyBytes);
            encrypt = encode(encryptBytes);
        } catch (Exception e) {
            e.printStackTrace();
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
     * @return
     * @throws Exception
     */
    private static byte[] initKey() throws Exception {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGenerator.init(128);
        final SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    /**
     * 加密
     *
     * @param content  需要加密的内容
     * @param keyBytes 加密密码
     * @return
     */
    private static byte[] encrypt(String content, byte[] keyBytes) throws Exception {
        final byte[] byteContent = content.getBytes(CHAR_ENCODING);

        final SecretKeySpec key = new SecretKeySpec(keyBytes, AES_ALGORITHM);

        final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
        return cipher.doFinal(byteContent);
    }

    /**
     * 解密
     *
     * @param content  待解密内容
     * @param keyBytes 解密密钥
     * @return
     */
    private static byte[] decrypt(byte[] content, byte[] keyBytes) throws Exception {
        final SecretKeySpec key = new SecretKeySpec(keyBytes, AES_ALGORITHM);

        final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
        return cipher.doFinal(content);
    }

}
