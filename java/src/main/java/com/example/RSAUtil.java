package com.example;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * Created by BlingBling on 2017/3/16.
 */

public class RSAUtil {

    private RSAUtil() {}

    private static final String RSA_ALGORITHM = "RSA";
    /**
     * 加密算法RSA
     */
    private static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

    /**
     * 签名算法
     */
    private static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    /**
     * 编码
     */
    private static final String CHAR_ENCODING = "UTF-8";

    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

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
     * 用私钥对信息生成数字签名
     *
     * @param data       数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     */
    public static String sign(String data, String privateKey) {
        String sign = null;
        try {
            byte[] dataBytes = data.getBytes(CHAR_ENCODING);
            PrivateKey key = getPrivateKey(decode(privateKey));

            byte[] signBytes = sign(dataBytes, key);
            sign = encode(signBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sign;
    }

    /**
     * 校验数字签名
     *
     * @param data      数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign      数字签名(BASE64编码)
     * @return
     */
    public static boolean verify(String data, String publicKey, String sign) {
        boolean verify = false;
        try {
            byte[] dataBytes = data.getBytes(CHAR_ENCODING);
            PublicKey key = getPublicKey(decode(publicKey));
            byte[] signBytes = decode(sign);

            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(key);
            signature.update(dataBytes);
            verify = signature.verify(signBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return verify;
    }

    /**
     * 公钥加密
     *
     * @param data      源数据
     * @param publicKey 公钥(BASE64编码)
     * @return BASE64编码的加密数据
     */
    public static String encryptByPublicKey(String data, String publicKey) {
        String encryptData = null;
        try {
            byte[] dataBytes = data.getBytes(CHAR_ENCODING);
            PublicKey key = getPublicKey(decode(publicKey));

            byte[] encryptDataBytes = encryptByPublicKey(dataBytes, key);
            encryptData = encode(encryptDataBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptData;
    }

    /**
     * 私钥加密
     *
     * @param data       源数据
     * @param privateKey 私钥(BASE64编码)
     * @return BASE64编码的加密数据
     */
    public static String encryptByPrivateKey(String data, String privateKey) {
        String encryptData = null;
        try {
            byte[] dataBytes = data.getBytes(CHAR_ENCODING);
            PrivateKey key = getPrivateKey(decode(privateKey));

            byte[] encryptDataBytes = encryptByPrivateKey(dataBytes, key);
            encryptData = encode(encryptDataBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptData;
    }

    /**
     * 公钥解密
     *
     * @param encryptedData 私钥加密的数据(BASE64编码)
     * @param publicKey     公钥(BASE64编码)
     * @return 私钥加密前的数据
     */
    public static String decryptByPublicKey(String encryptedData, String publicKey) {
        String data = null;
        try {
            byte[] dataBytes = decode(encryptedData);
            PublicKey key = getPublicKey(decode(publicKey));

            byte[] decryptDataBytes = decryptByPublicKey(dataBytes, key);
            data = new String(decryptDataBytes, CHAR_ENCODING);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return data;
    }

    /**
     * 私钥解密
     *
     * @param encryptedData 公钥加密的数据(BASE64编码)
     * @param privateKey    私钥(BASE64编码)
     * @return 公钥加密前的数据
     */
    public static String decryptByPrivateKey(String encryptedData, String privateKey) {
        String data = null;
        try {
            byte[] dataBytes = decode(encryptedData);
            PrivateKey key = getPrivateKey(decode(privateKey));

            byte[] decryptDataBytes = decryptByPrivateKey(dataBytes, key);
            data = new String(decryptDataBytes, CHAR_ENCODING);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return data;
    }

    /**
     * 生成RSA密钥对(默认密钥长度为1024)
     *
     * @return
     * @throws Exception
     */
    public static KeyPair initKeyPair() throws Exception {
        return initKeyPair(1024);
    }

    /**
     * 生成RSA密钥对
     *
     * @param length 密钥长度，范围：512～2048
     * @return
     * @throws Exception
     */
    public static KeyPair initKeyPair(int length) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGen.initialize(length);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        return keyPair;
    }

    //**************************************提供一些基础操作********************************************

    /**
     * 获取公钥
     *
     * @param keyBytes
     * @return
     * @throws Exception
     */
    public static PublicKey getPublicKey(byte[] keyBytes) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        return publicKey;
    }

    /**
     * 获取私钥
     *
     * @param keyBytes
     * @return
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        return privateKey;
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       数据
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * 校验数字签名
     *
     * @param data      已加密数据
     * @param publicKey 公钥
     * @param signBytes 数字签名
     * @return
     * @throws Exception
     */
    public static boolean verify(byte[] data, PublicKey publicKey, byte[] signBytes) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signBytes);
    }

    /**
     * 公钥加密
     *
     * @param data      源数据
     * @param publicKey 公钥
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = null;
        ByteArrayOutputStream out = null;
        try {
            out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            int inputLen = data.length;
            // 对数据分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            encryptedData = out.toByteArray();
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (Exception e) {}
            }
        }
        return encryptedData;
    }

    /**
     * 私钥加密
     *
     * @param data       源数据
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] encryptedData = null;
        ByteArrayOutputStream out = null;
        try {
            out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            int inputLen = data.length;
            // 对数据分段加密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            encryptedData = out.toByteArray();
            out.close();
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (Exception e) {}
            }
        }
        return encryptedData;
    }

    /**
     * 公钥解密
     *
     * @param encryptedData 公钥加密的数据
     * @param publicKey     公钥
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedData = null;
        ByteArrayOutputStream out = null;
        try {
            out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            int inputLen = encryptedData.length;
            // 对数据分段解密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_DECRYPT_BLOCK;
            }
            decryptedData = out.toByteArray();
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (Exception e) {}
            }
        }
        return decryptedData;
    }

    /**
     * 私钥解密
     *
     * @param encryptedData 公钥加密的数据
     * @param privateKey    私钥
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedData = null;
        ByteArrayOutputStream out = null;
        try {
            out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            int inputLen = encryptedData.length;
            // 对数据分段解密
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_DECRYPT_BLOCK;
            }
            decryptedData = out.toByteArray();
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (Exception e) {}
            }
        }
        return decryptedData;
    }
}