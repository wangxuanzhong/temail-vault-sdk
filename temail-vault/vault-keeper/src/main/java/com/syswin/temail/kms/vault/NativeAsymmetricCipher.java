package com.syswin.temail.kms.vault;

import static com.syswin.temail.kms.vault.CipherAlgorithm.SM2;

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
    return new byte[0];
  }

  @Override
  public String decrypt(byte[] privateKey, byte[] encryptedBytes) {
    return null;
  }

  @Override
  public byte[] sign(byte[] privateKey, byte[] unsigned) {
    return new byte[0];
  }

  @Override
  public boolean verify(byte[] publicKey, byte[] unsigned, byte[] signed) {
    return false;
  }

  @Override
  public CipherAlgorithm algorithm() {
    return SM2;
  }
}
