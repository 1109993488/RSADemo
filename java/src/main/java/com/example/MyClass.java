package com.example;


import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class MyClass {

    public static void main(String[] args) throws Exception {
//        initKey();

        test1();
        print("------------------------------------");
        test2();
        print("------------------------------------");
        test3();
    }

    /**
     * PublicKey加密，PrivateKey解密
     */
    private static void test1() throws Exception {
        byte[] data = DATA.getBytes("utf-8");
        PublicKey publicKey = RSAUtils.getPublicKey(Base64.decode(PUBLIC_KEY));
        PrivateKey privateKey = RSAUtils.getPrivateKey(Base64.decode(PRIVATE_KEY));
        byte[] encryptBytes = RSAUtils.encryptByPublicKey(data, publicKey);
        print("公钥加密后的数据为", Base64.encode(encryptBytes));
        byte[] decryptDataBytes = RSAUtils.decryptByPrivateKey(encryptBytes, privateKey);
        print("私钥解密后的数据为", new String(decryptDataBytes, "utf-8"));

    }

    /**
     * PrivateKey加密，PublicKey解密
     */
    private static void test2() throws Exception {
        byte[] data = DATA.getBytes("utf-8");
        PublicKey publicKey = RSAUtils.getPublicKey(Base64.decode(PUBLIC_KEY));
        PrivateKey privateKey = RSAUtils.getPrivateKey(Base64.decode(PRIVATE_KEY));
        byte[] encryptBytes = RSAUtils.encryptByPrivateKey(data, privateKey);
        print("私钥加密后的数据为", Base64.encode(encryptBytes));
        byte[] decryptDataBytes = RSAUtils.decryptByPublicKey(encryptBytes, publicKey);
        print("公钥解密后的数据为", new String(decryptDataBytes, "utf-8"));


        print("------------------------------------");
        print("私钥签名——公钥验证签名");

        byte[] signBytes = RSAUtils.sign(encryptBytes, privateKey);
        String sign = Base64.encode(signBytes);
        boolean status = RSAUtils.verify(encryptBytes, publicKey, signBytes);
        print("私钥加密的签名", sign);
        print("公钥验证签名", "结果为:" + status);
    }

    private static void test3() throws Exception {
        String appPublicKeyEncryptData = "IVcu0+pC7WBbCSmhGOD41FREIZPyfLAkKTYO3FQm6iXaP+m17FJMoxECnGURfye31zbF8SYThtjCeHZYWK4aY3PY8cqX8nK6inw16Lymnd4DDfhwt2/66a/38u8h6vh7w7gxrfk4QwqU4cZ74hlftRDNwFk5B06jQWRCRW3upmc=";
        String appPrivateKeyEncryptData = "eILmLJZLb9luxTAE+vQ/2iQpYg/UWEoB7cLrLZb9i40kpxT5ky7gi/vF3Vd5Fj2WgAWwA8eBkpffgeDupBu5RukhvO1lEbvdQH09luA9ejCFFcRoAmSYFYc/xBtHhpLXXwH2PGbL6bk2ugyiBbSsYJEm6BT2dD6pNvVrA0VJLzI=";

        PublicKey publicKey = RSAUtils.getPublicKey(Base64.decode(PUBLIC_KEY));
        PrivateKey privateKey = RSAUtils.getPrivateKey(Base64.decode(PRIVATE_KEY));

        byte[] decryptDataBytesByPrivateKey = RSAUtils.decryptByPrivateKey(Base64.decode(appPublicKeyEncryptData), privateKey);
        print("私钥解密后的数据为", new String(decryptDataBytesByPrivateKey, "utf-8"));

        print("------------------------------------");

        byte[] decryptDataBytesByPublicKey = RSAUtils.decryptByPublicKey(Base64.decode(appPrivateKeyEncryptData), publicKey);
        print("公钥解密后的数据为", new String(decryptDataBytesByPublicKey, "utf-8"));
    }

    private static void print(String string) {
        System.out.println(string);
    }

    private static void print(String tag, String string) {
        System.out.println(tag + "  " + string);
    }

    //initKey()生成的一种
    private static final String PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIcDbbNASadtQGZSI6ZiHUAj1xra+6ma0LVKgPoV/fopkKuenxln26WPRQoxvHvMaaUacZpnF39+i3hUwciQe6kZroAVQpVxa9Hw3IGKXbf+IF0dfi06T0+8OMGqZMvThmr8Kv4tUKo/SASFXteDubcCj5zs/MvJS+jXfm+fDUFlAgMBAAECgYBZexk6gvINx+e1qNy9yisOtnI690VxzAxlCuLeXLL+GIwsYi2Z3e6CFKkyL3J3LiwaY6NFLOwy8ICpGKtyLOf3W5LxDlPEmvmkNjwk7F0GwGkCZMyssx94wUjPD5nO4HDhhoOhfwNWDVd36hYzkwthutek6PKs4fybDrmtbOuhBQJBANK2uBNDNmZXtuB7fEKnSMKy7j7DRuFHrPBHnuo+2fTxw2mdVjZ6pRlnDuGEpdI/CMgtvaGCdDKrjHxtohDNMAsCQQCkB7550KCes2FiaF6NLxTLSs7LNxAZ4cfFMi8tpq6By4VQpC6xs7SlRAKjffsPxP9lpB1moKK1KmCLWAYFcQpPAkEAp7RFTQ9xfILTSlb9zw7VGiDO/aTuBN7HBXX7RPRBBHJm1OgkdbenL1CWx2aLk4oXszq0cpchZDKk3WNkWXr1gQJAJvokG+QkVrG/YVf1p8zZPxlunEFgVRYel1A+f7WM4BDRhAEPi3Bta5wGmHz2LKAeJDPkPJ/NKgmA2Xu4KpDa5wJAan3L03UhxzkYCk4Hy6purQjp8CEMaY6ChJbrCPNg1O746QuSOhHQMDP1GASDPk6nvpFr+MK53Th4IvCEALC1Mw==";
    private static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHA22zQEmnbUBmUiOmYh1AI9ca2vupmtC1SoD6Ff36KZCrnp8ZZ9ulj0UKMbx7zGmlGnGaZxd/fot4VMHIkHupGa6AFUKVcWvR8NyBil23/iBdHX4tOk9PvDjBqmTL04Zq/Cr+LVCqP0gEhV7Xg7m3Ao+c7PzLyUvo135vnw1BZQIDAQAB";

    private static final String DATA = "这是数据，这是数据，这是数据。";


    private static void initKey() throws Exception {
        KeyPair keyPair = RSAUtils.genKeyPair();
        String privateKey = Base64.encode(keyPair.getPrivate().getEncoded());
        String publicKey = Base64.encode(keyPair.getPublic().getEncoded());
        System.out.println("PrivateKey-> " + privateKey);
        System.out.println("PublicKey-> " + publicKey);
    }

}
