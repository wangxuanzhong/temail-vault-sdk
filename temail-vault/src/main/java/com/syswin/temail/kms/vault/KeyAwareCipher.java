package com.syswin.temail.kms.vault;

public interface KeyAwareCipher {

  byte[] encrypt(String userId, String plaintext) throws Exception;

  String decrypt(String userId, byte[] encryptedBytes) throws Exception;

  byte[] sign(String userId, byte[] unsigned) throws Exception;

  boolean verify(String userId, byte[] unsigned, byte[] signed);

  void revoke(String userId);

  CipherAlgorithm algorithm();
}
