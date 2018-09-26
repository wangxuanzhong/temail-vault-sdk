//package com.syswin.temail.kms.vault;
//
//import static com.seanyinx.github.unit.scaffolding.AssertUtils.expectFailing;
//import static org.assertj.core.api.Assertions.assertThat;
//
//import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
//import org.junit.Ignore;
//import org.junit.Test;
//
//@Ignore
//public class NativeAsymmetricCipherTest {
//
//  private final NativeAsymmetricCipher cipher = new NativeAsymmetricCipher();
//  private final KeyPair keyPair = cipher.getKeyPair();
//
//  @Test
//  public void shouldGenerateKeyPair() {
//    assertThat(keyPair.getPublic()).isEqualTo("hello");
//    assertThat(keyPair.getPrivate()).isEqualTo("world");
//  }
//
//  @Test
//  public void shouldEncrypt() {
//    String encrypted = cipher.encrypt(keyPair.getPublic(), "Sean");
//
//    assertThat(encrypted).isEqualTo("hello Sean");
//  }
//
//  @Test
//  public void shouldFailEncryption() {
//    try {
//      cipher.encrypt("blah", "Sean");
//      expectFailing(VaultCipherException.class);
//    } catch (VaultCipherException e) {
//      assertThat(e).hasMessage("Failed to encrypt text");
//    }
//  }
//
//  @Test
//  public void shouldDecrypt() {
//    String plaintext = cipher.decrypt(keyPair.getPrivate(), "Sean");
//
//    assertThat(plaintext).isEqualTo("Sean's world");
//  }
//
//  @Test
//  public void shouldSign() {
//    String signature = cipher.sign(keyPair.getPrivate(), "Sean");
//
//    assertThat(signature).isEqualTo("world of Sean");
//  }
//
//  @Test
//  public void shouldVerify() {
//    boolean verified = cipher.verify(keyPair.getPublic(), "Sean", "Sean");
//    assertThat(verified).isTrue();
//
//    verified = cipher.verify(keyPair.getPublic(), "Sean", "Jack");
//    assertThat(verified).isFalse();
//  }
//}
