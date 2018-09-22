package com.syswin.temail.kms.vault;

public interface PublicKeyCipher {

  String encrypt(String publicKey, String plaintext);

  boolean verify(String publicKey, String plaintext, String signature);

  CipherAlgorithm algorithm();
}
