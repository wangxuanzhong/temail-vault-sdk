package com.syswin.temail.kms.vault;

import static com.seanyinx.github.unit.scaffolding.Randomness.uniquify;
import static com.syswin.temail.kms.vault.CipherAlgorithm.ECDSA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.util.Optional;
import org.junit.Test;
import org.mockito.Mockito;

public class DelegatingKeyAwareAsymmetricCipherTest {

  private final String tenantId = uniquify("tenantId");
  private final String userId = uniquify("userId");
  private final String plaintext = uniquify("plaintext");
  private final String encrypted = uniquify("encrypted");
  private final String signature = uniquify("signature");

  private final String publicKey = "abc";
  private final String privateKey = "xyz";
  private final KeyPair keyPair = new KeyPair(privateKey.getBytes(), publicKey.getBytes());

  private final AsymmetricCipher vaultCipher = Mockito.mock(AsymmetricCipher.class);
  private final KeyRegistry keyRegistry = Mockito.mock(KeyRegistry.class);
  private final KeyAwareAsymmetricCipher keyAwareCipher = new DelegatingKeyAwareAsymmetricCipher(tenantId, vaultCipher, keyRegistry);

  @Test
  public void encryptWithKeyOfRegisteredUser() {
    when(keyRegistry.retrieve(tenantId, userId)).thenReturn(keyPair);
    when(vaultCipher.encrypt(publicKey, plaintext)).thenReturn(encrypted);

    String encrypted = keyAwareCipher.encrypt(userId, plaintext);
    assertThat(encrypted).isEqualTo(this.encrypted);
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void decryptWithKeyOfRegisteredUser() {
    when(keyRegistry.retrieve(tenantId, userId)).thenReturn(keyPair);
    when(vaultCipher.decrypt(privateKey, encrypted)).thenReturn(plaintext);

    String plaintext = keyAwareCipher.decrypt(userId, encrypted);
    assertThat(plaintext).isEqualTo(this.plaintext);
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void signWithKeyOfRegisteredUser() {
    when(keyRegistry.retrieve(tenantId, userId)).thenReturn(keyPair);
    when(vaultCipher.sign(privateKey, plaintext)).thenReturn(signature);

    String signature = keyAwareCipher.sign(userId, plaintext);
    assertThat(signature).isEqualTo(this.signature);
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void verifyWithKeyOfRegisteredUser() {
    when(keyRegistry.retrieve(tenantId, userId)).thenReturn(keyPair);
    when(vaultCipher.verify(publicKey, plaintext, signature)).thenReturn(true);

    boolean verified = keyAwareCipher.verify(userId, plaintext, signature);
    assertThat(verified).isTrue();
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void registerUserInRegistry() {
    when(keyRegistry.register(tenantId, userId)).thenReturn(keyPair);

    String publicKey = keyAwareCipher.register(userId);

    assertThat(publicKey).isEqualTo(this.publicKey);
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test (expected = VaultCipherException.class)
  public void blowsUpIfNoSuchUserRegistered() {
    when(keyRegistry.retrieve(tenantId, userId)).thenThrow(VaultCipherException.class);
    keyAwareCipher.decrypt(userId, encrypted);
  }

  @Test
  public void shouldUseAlgorithmOfUnderlyingCipher() {
    when(vaultCipher.algorithm()).thenReturn(ECDSA);

    CipherAlgorithm algorithm = keyAwareCipher.algorithm();

    assertThat(algorithm).isEqualTo(ECDSA);
  }

  @Test
  public void shouldGetPublicKeyOfRegisteredUser() {
    when(keyRegistry.retrieve(tenantId, userId)).thenReturn(keyPair);

    Optional<String> publicKey = keyAwareCipher.publicKey(userId);

    assertThat(publicKey).contains(this.publicKey);
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void shouldGetNothingOfNonExistingUser() {
    when(keyRegistry.retrieve(tenantId, userId)).thenThrow(VaultCipherException.class);

    Optional<String> publicKey = keyAwareCipher.publicKey(userId);

    assertThat(publicKey).isNotPresent();
    verify(vaultCipher, never()).getKeyPair();
  }

  @Test
  public void shouldRemoveUser() {
    keyAwareCipher.revoke(userId);

    verify(keyRegistry).remove(tenantId, userId);
  }
}
