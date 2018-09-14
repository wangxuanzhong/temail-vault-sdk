package com.syswin.temail.kms.vault;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface Security {

  KeyPair getKeyPair() throws Exception;

  byte[] encrypt(PublicKey publicKey, String plaintext) throws Exception;

  String decrypt(PrivateKey privateKey, byte[] encryptedBytes) throws Exception;

  byte[] sign(PrivateKey privateKey, byte[] unsigned) throws Exception;

  boolean verify(PublicKey publicKey, byte[] unsigned, byte[] signed);
}
