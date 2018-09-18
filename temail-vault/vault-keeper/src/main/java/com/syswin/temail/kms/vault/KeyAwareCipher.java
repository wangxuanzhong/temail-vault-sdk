package com.syswin.temail.kms.vault;

public interface KeyAwareCipher {

  byte[] encrypt(String userId, String plaintext);

  String decrypt(String userId, byte[] encryptedBytes);

  byte[] sign(String userId, String plaintext);

  boolean verify(String userId, String plaintext, byte[] signed);

  void revoke(String userId);

  CipherAlgorithm algorithm();
}
