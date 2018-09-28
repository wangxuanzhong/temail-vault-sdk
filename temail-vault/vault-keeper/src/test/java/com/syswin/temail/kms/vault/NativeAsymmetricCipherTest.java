package com.syswin.temail.kms.vault;

import static com.seanyinx.github.unit.scaffolding.AssertUtils.expectFailing;
import static org.assertj.core.api.Assertions.assertThat;

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import org.junit.Ignore;
import org.junit.Test;

@Ignore
public class NativeAsymmetricCipherTest {

  private final NativeAsymmetricCipher cipher = new NativeAsymmetricCipher();
  private final KeyPair keyPair = cipher.getKeyPair();

  @Test
  public void shouldGenerateKeyPair() {
    assertThat(keyPair.getPublic()).isNotNull();
    assertThat(keyPair.getPrivate()).isNotNull();
  }

  @Test
  public void shouldEncrypt() {
    String encrypted = cipher.encrypt(keyPair.getPublic(), "Sean");
    assertThat(encrypted).isNotNull();

    String plaintext = cipher.decrypt(keyPair.getPrivate(), encrypted);
    assertThat(plaintext).isEqualTo("Sean");
  }

  @Test
  public void shouldFailEncryption() {
    try {
      cipher.encrypt("blah", "Sean");
      expectFailing(VaultCipherException.class);
    } catch (VaultCipherException e) {
      assertThat(e).hasMessage("Invalid public or private key");
    }
  }

  @Test
  public void shouldSign() {
    String signature = cipher.sign(keyPair.getPrivate(), "Sean");
    assertThat(signature).isNotNull();

    boolean verified = cipher.verify(keyPair.getPublic(), "Sean", signature);
    assertThat(verified).isTrue();

    verified = cipher.verify(keyPair.getPublic(), "Jack", signature);
    assertThat(verified).isFalse();
  }
}
