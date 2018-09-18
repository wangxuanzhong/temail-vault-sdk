package com.syswin.temail.kms.vault;

import static com.syswin.temail.kms.vault.CipherAlgorithm.SM2;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.syswin.temail.vault.jni.CipherJni;

class NativeAsymmetricCipher implements AsymmetricCipher {

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
    return cipher.verify(publicKey, plaintext, signature);
  }

  @Override
  public CipherAlgorithm algorithm() {
    return SM2;
  }
}
