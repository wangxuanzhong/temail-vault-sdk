package com.syswin.temail.kms.vault;

import static com.syswin.temail.kms.vault.CipherAlgorithm.SM2;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.syswin.temail.vault.jni.CipherJni;
import java.lang.invoke.MethodHandles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class NativeAsymmetricCipher implements AsymmetricCipher {
  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private final CipherJni cipher;

  NativeAsymmetricCipher() {
    cipher = new CipherJni();
  }

  @Override
  public KeyPair getKeyPair() {
    CipherJni.KeyPair keyPair = cipher.generateKeyPair();
    return new KeyPair(keyPair.privateKey(), keyPair.publicKey());
  }

  @Override
  public byte[] encrypt(byte[] publicKey, String plaintext) {
    return cipher.encrypt(publicKey, plaintext);
  }

  @Override
  public String decrypt(byte[] privateKey, byte[] encryptedBytes) {
    return new String(cipher.decrypt(privateKey, encryptedBytes), UTF_8);
  }

  @Override
  public byte[] sign(byte[] privateKey, String plaintext) {
    return cipher.sign(privateKey, plaintext);
  }

  @Override
  public boolean verify(byte[] publicKey, String plaintext, byte[] signature) {
    try {
      return cipher.verify(publicKey, plaintext, signature);
    } catch (Exception e) {
      LOG.error("Failed to verify signature of [{}]", plaintext, e);
      return false;
    }
  }

  @Override
  public CipherAlgorithm algorithm() {
    return SM2;
  }
}
