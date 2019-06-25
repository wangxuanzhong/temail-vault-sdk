package com.syswin.temail.kms.vault;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

public class NullSymmetricCipherTest {

  private final NullSymmetricCipher cipher = new NullSymmetricCipher();

  @Test
  public void emptyKey() {
    String key = cipher.getKey("hello");

    assertThat(key).isEmpty();
  }

  @Test
  public void encryptionDoesNothing() {
    String plaintext = "plaintext";
    String encrypted = cipher.encrypt("hello", plaintext);

    assertThat(encrypted).isEqualTo(plaintext);
  }

  @Test
  public void decryptionDoesNothing() {
    String encrypted = "encrypted";
    String plaintext = cipher.decrypt("hello", encrypted);

    assertThat(plaintext).isEqualTo(encrypted);
  }
}