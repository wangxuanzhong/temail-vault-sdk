package com.syswin.temail.kms.vault;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface AsymmetricCipher {

  KeyPair getKeyPair();

  byte[] encrypt(PublicKey publicKey, String plaintext);

  String decrypt(PrivateKey privateKey, byte[] encryptedBytes);

  byte[] sign(PrivateKey privateKey, byte[] unsigned);

  boolean verify(PublicKey publicKey, byte[] unsigned, byte[] signed);

  CipherAlgorithm algorithm();
}
