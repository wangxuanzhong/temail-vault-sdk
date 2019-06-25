package com.syswin.temail.kms.vault;

import com.syswin.temail.kms.vault.aes.SymmetricCipher;

public class FakeSymmetricCipher implements SymmetricCipher {

  @Override
  public String getKey(String text) {
    return null;
  }

  @Override
  public String encrypt(String key, String plaintext) {
    return null;
  }

  @Override
  public String decrypt(String key, String encrypted) {
    return null;
  }
}
