package com.syswin.temail.kms.vault;

import static com.seanyinx.github.unit.scaffolding.AssertUtils.expectFailing;
import static com.seanyinx.github.unit.scaffolding.Randomness.uniquify;
import static com.syswin.temail.kms.vault.CipherAlgorithm.SM2;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.util.Optional;
import org.junit.Test;
import org.mockito.Mockito;

public class DelegatingKeyAwareAsymmetricCipherTest {

  private final String userId = uniquify("userId");
  private final String plaintext = uniquify("plaintext");
  private final byte[] encrypted = uniquify("encrypted").getBytes();
  private final byte[] signature = uniquify("signature").getBytes();

  private final byte[] publicKey = "abc".getBytes();
  private final byte[] privateKey = "xyz".getBytes();
  private final KeyPair keyPair = new KeyPair(privateKey, publicKey);

  private final AsymmetricCipher vaultCipher = Mockito.mock(AsymmetricCipher.class);
  private final KeyRegistry keyRegistry = Mockito.mock(KeyRegistry.class);
  private final KeyAwareAsymmetricCipher keyAwareCipher = new DelegatingKeyAwareAsymmetricCipher(vaultCipher, keyRegistry);

  @Test
  public void encryptWithKeyOfRegisteredUser() {
    when(keyRegistry.retrieve(userId)).thenReturn(keyPair);
    when(vaultCipher.encrypt(publicKey, plaintext)).thenReturn(encrypted);

    byte[] encrypted = keyAwareCipher.encrypt(userId, plaintext);
    assertThat(encrypted).isEqualTo(this.encrypted);
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void decryptWithKeyOfRegisteredUser() {
    when(keyRegistry.retrieve(userId)).thenReturn(keyPair);
    when(vaultCipher.decrypt(privateKey, encrypted)).thenReturn(plaintext);

    String plaintext = keyAwareCipher.decrypt(userId, encrypted);
    assertThat(plaintext).isEqualTo(this.plaintext);
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void signWithKeyOfRegisteredUser() {
    when(keyRegistry.retrieve(userId)).thenReturn(keyPair);
    when(vaultCipher.sign(privateKey, plaintext)).thenReturn(signature);

    byte[] signature = keyAwareCipher.sign(userId, plaintext);
    assertThat(signature).isEqualTo(this.signature);
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void verifyWithKeyOfRegisteredUser() {
    when(keyRegistry.retrieve(userId)).thenReturn(keyPair);
    when(vaultCipher.verify(publicKey, plaintext, signature)).thenReturn(true);

    boolean verified = keyAwareCipher.verify(userId, plaintext, signature);
    assertThat(verified).isTrue();
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void registerUserInRegistry() {
    when(keyRegistry.register(userId)).thenReturn(keyPair);

    byte[] publicKey = keyAwareCipher.register(userId);

    assertThat(publicKey).isEqualTo(this.publicKey);
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void blowsUpIfNoSuchUserRegistered() {
    try {
      keyAwareCipher.decrypt(userId, encrypted);
      expectFailing(VaultCipherException.class);
    } catch (VaultCipherException e) {
      assertThat(e).hasMessage("No such user registered: " + userId);
    }
  }

  @Test
  public void shouldUseAlgorithmOfUnderlyingCipher() {
    when(vaultCipher.algorithm()).thenReturn(SM2);

    CipherAlgorithm algorithm = keyAwareCipher.algorithm();

    assertThat(algorithm).isEqualTo(SM2);
  }

  @Test
  public void shouldGetPublicKeyOfRegisteredUser() {
    when(keyRegistry.retrieve(userId)).thenReturn(keyPair);

    Optional<byte[]> publicKey = keyAwareCipher.publicKey(userId);

    assertThat(publicKey).contains(this.publicKey);
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void shouldRemoveUser() {
    keyAwareCipher.revoke(userId);

    verify(keyRegistry).remove(userId);
  }
}
