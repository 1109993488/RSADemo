package com.example.utils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;

/**
 * Created by BlingBling on 2017/3/17.
 */

public class MD5Util {
    private MD5Util() {}

    /**
     * 编码
     */
    private static final String CHAR_ENCODING = "UTF-8";
    private static final String MD5 = "MD5";

    /**
     * MD5加密
     *
     * @param data
     * @return
     */
    public static String digest(String data) {
        String digest = null;
        try {
            //确定计算方法
            final MessageDigest md5 = MessageDigest.getInstance(MD5);
            md5.update(data.getBytes(CHAR_ENCODING));
            //加密后的字符串
            final byte[] digestBytes = md5.digest();
            digest = byteArrayToHexString(digestBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return digest;
    }

    /**
     * 计算文件的MD5
     * @param file
     * @return
     */
    public static String digest(File file) {
        String digest = null;
        BufferedInputStream bis = null;
        try {
            bis = new BufferedInputStream(new FileInputStream(file));
            //确定计算方法
            final MessageDigest md5 = MessageDigest.getInstance(MD5);
            final byte[] buffer = new byte[8192];
            int len;
            while ((len = bis.read(buffer)) != -1) {
                md5.update(buffer, 0, len);
            }
            //加密后的字符串
            final byte[] digestBytes = md5.digest();
            digest = byteArrayToHexString(digestBytes);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (bis != null) {
                try {bis.close();} catch (IOException e) { }
            }
        }
        return digest;
    }

    /**
     * byte数组转换为16进制字符串
     *
     * @param bytes
     * @return
     */
    public static String byteArrayToHexString(byte[] bytes) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0, len = bytes.length; i < len; i++) {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16)
                    .substring(1));
        }
        return sb.toString();
    }

    /**
     * 16进制字符串转换为byte数组
     *
     * @param data
     * @return
     */
    public static byte[] hexStringToByteArray(String data) {
        int k = 0;
        final byte[] results = new byte[data.length() / 2];
        for (int i = 0, len = data.length(); i < len; ) {
            results[k] = (byte) (Character.digit(data.charAt(i++), 16) << 4);
            results[k] += (byte) (Character.digit(data.charAt(i++), 16));
            k++;
        }
        return results;
    }
}
