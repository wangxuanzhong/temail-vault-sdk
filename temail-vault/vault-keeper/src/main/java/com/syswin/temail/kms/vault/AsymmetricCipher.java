package com.syswin.temail.kms.vault;


public interface AsymmetricCipher {

  KeyPair getKeyPair();

  byte[] encrypt(byte[] publicKey, String plaintext);

  String decrypt(byte[] privateKey, byte[] encryptedBytes);

  byte[] sign(byte[] privateKey, byte[] unsigned);

  boolean verify(byte[] publicKey, byte[] unsigned, byte[] signed);

  CipherAlgorithm algorithm();
}
