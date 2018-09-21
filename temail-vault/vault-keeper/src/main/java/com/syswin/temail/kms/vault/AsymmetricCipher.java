package com.syswin.temail.kms.vault;


public interface AsymmetricCipher {

  KeyPair getKeyPair();

  String encrypt(String publicKey, String plaintext);

  String decrypt(String privateKey, String encrypted);

  String sign(String privateKey, String plaintext);

  boolean verify(String publicKey, String plaintext, String signature);

  CipherAlgorithm algorithm();
}
