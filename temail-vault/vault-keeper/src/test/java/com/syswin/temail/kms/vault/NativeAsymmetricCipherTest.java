package com.syswin.temail.kms.vault;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

public class NativeAsymmetricCipherTest {

  private final NativeAsymmetricCipher cipher = new NativeAsymmetricCipher();
  private final KeyPair keyPair = cipher.getKeyPair();

  @Test
  public void shouldGenerateKeyPair() {
    assertThat(new String(keyPair.getPublic())).isEqualTo("hello");
    assertThat(new String(keyPair.getPrivate())).isEqualTo("world");
  }

  @Test
  public void shouldEncrypt() {
    byte[] encrypted = cipher.encrypt(keyPair.getPublic(), "Sean");

    assertThat(new String(encrypted)).isEqualTo("hello Sean");
  }

  @Test
  public void shouldDecrypt() {
    String plaintext = cipher.decrypt(keyPair.getPrivate(), "Sean".getBytes());

    assertThat(plaintext).isEqualTo("Sean's world");
  }

  @Test
  public void shouldSign() {
    byte[] signature = cipher.sign(keyPair.getPrivate(), "Sean");

    assertThat(new String(signature)).isEqualTo("world of Sean");
  }

  @Test
  public void shouldVerify() {
    boolean verified = cipher.verify(keyPair.getPublic(), "Sean", "Sean".getBytes());
    assertThat(verified).isTrue();

    verified = cipher.verify(keyPair.getPublic(), "Sean", "Jack".getBytes());
    assertThat(verified).isFalse();
  }
}
