package com.lick.controller;

import java.util.Map;

import static com.lick.util.RSAUtils.*;

public class RSATest {
    public static void main(String[] args) throws Exception {
        Map<String, Object> initKey = initKey();
        String publicKeyStr = getPublicKeyStr(initKey);
        String privateKeyStr = getPrivateKeyStr(initKey);
        encryptFile("D:/hello/test.pdf","D:/hello/testNeedDecode.pdf",publicKeyStr);
        decryptFile("D:/hello/testNeedDecode.pdf","D:/hello/testFinal.pdf",privateKeyStr);

    }
}
