package com.syswin.temail.kms.vault;

public interface KeyAwareCipher {

  byte[] encrypt(String userId, String plaintext);

  String decrypt(String userId, byte[] encryptedBytes);

  byte[] sign(String userId, byte[] unsigned);

  boolean verify(String userId, byte[] unsigned, byte[] signed);

  void revoke(String userId);

  CipherAlgorithm algorithm();
}
