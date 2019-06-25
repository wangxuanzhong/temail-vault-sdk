package com.syswin.temail.kms.vault;

import com.syswin.temail.kms.vault.aes.SymmetricCipher;

class NullSymmetricCipher implements SymmetricCipher {

  @Override
  public String getKey(String text) {
    return "";
  }

  @Override
  public String encrypt(String key, String plaintext) {
    return plaintext;
  }

  @Override
  public String decrypt(String key, String encrypted) {
    return encrypted;
  }
}
