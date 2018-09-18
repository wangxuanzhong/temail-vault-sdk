package com.syswin.temail.kms.vault;


public interface AsymmetricCipher {

  KeyPair getKeyPair();

  byte[] encrypt(byte[] publicKey, String plaintext);

  String decrypt(byte[] privateKey, byte[] encryptedBytes);

  byte[] sign(byte[] privateKey, String plaintext);

  boolean verify(byte[] publicKey, String plaintext, byte[] signature);

  CipherAlgorithm algorithm();
}
