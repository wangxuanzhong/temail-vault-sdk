package com.syswin.temail.kms.vault;

import static com.seanyinx.github.unit.scaffolding.AssertUtils.expectFailing;
import static com.seanyinx.github.unit.scaffolding.Randomness.uniquify;
import static com.syswin.temail.kms.vault.CipherAlgorithm.SM2;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;
import org.junit.Test;
import org.mockito.Mockito;

public class DelegatingKeyAwareAsymmetricCipherTest {

  private final String userId = uniquify("userId");
  private final String plaintext = uniquify("plaintext");
  private final byte[] encrypted = uniquify("encrypted").getBytes();
  private final byte[] signature = uniquify("signature").getBytes();

  private final PublicKey publicKey = Mockito.mock(PublicKey.class);
  private final PrivateKey privateKey = Mockito.mock(PrivateKey.class);

  private final AsymmetricCipher vaultCipher = Mockito.mock(AsymmetricCipher.class);
  private final KeyAwareAsymmetricCipher keyAwareCipher = new DelegatingKeyAwareAsymmetricCipher(vaultCipher);

  @Test
  public void encryptWithKeyOfRegisteredUser() throws Exception {
    when(vaultCipher.getKeyPair()).thenReturn(new KeyPair(publicKey, privateKey));
    when(vaultCipher.encrypt(publicKey, plaintext)).thenReturn(encrypted);

    PublicKey publicKey = keyAwareCipher.register(userId);
    assertThat(publicKey).isEqualTo(this.publicKey);

    byte[] encrypted = keyAwareCipher.encrypt(userId, plaintext);
    assertThat(encrypted).isEqualTo(this.encrypted);
  }

  @Test
  public void decryptWithKeyOfRegisteredUser() throws Exception {
    when(vaultCipher.getKeyPair()).thenReturn(new KeyPair(publicKey, privateKey));
    when(vaultCipher.decrypt(privateKey, encrypted)).thenReturn(plaintext);

    PublicKey publicKey = keyAwareCipher.register(userId);
    assertThat(publicKey).isEqualTo(this.publicKey);

    String plaintext = keyAwareCipher.decrypt(userId, encrypted);
    assertThat(plaintext).isEqualTo(this.plaintext);
  }

  @Test
  public void signWithKeyOfRegisteredUser() throws Exception {
    when(vaultCipher.getKeyPair()).thenReturn(new KeyPair(publicKey, privateKey));
    when(vaultCipher.sign(privateKey, encrypted)).thenReturn(signature);

    PublicKey publicKey = keyAwareCipher.register(userId);
    assertThat(publicKey).isEqualTo(this.publicKey);

    byte[] signature = keyAwareCipher.sign(userId, encrypted);
    assertThat(signature).isEqualTo(this.signature);
  }

  @Test
  public void verifyWithKeyOfRegisteredUser() {
    when(vaultCipher.getKeyPair()).thenReturn(new KeyPair(publicKey, privateKey));
    when(vaultCipher.verify(publicKey, plaintext.getBytes(), signature)).thenReturn(true);

    PublicKey publicKey = keyAwareCipher.register(userId);
    assertThat(publicKey).isEqualTo(this.publicKey);

    boolean verified = keyAwareCipher.verify(userId, plaintext.getBytes(), signature);
    assertThat(verified).isTrue();
  }

  @Test
  public void returnExistingKeyOnDuplicateRegistration() {
    when(vaultCipher.getKeyPair()).thenReturn(new KeyPair(publicKey, privateKey), new KeyPair(null, null));
    keyAwareCipher.register(userId);
    PublicKey publicKey = keyAwareCipher.register(userId);

    assertThat(publicKey).isEqualTo(this.publicKey);
  }

  @Test
  public void blowsUpIfNoSuchUserRegistered() throws Exception {
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
    when(vaultCipher.getKeyPair()).thenReturn(new KeyPair(publicKey, privateKey));

    keyAwareCipher.register(userId);
    Optional<PublicKey> publicKey = keyAwareCipher.publicKey(userId);

    assertThat(publicKey).contains(this.publicKey);
  }

  @Test
  public void shouldRemoveUser() {
    when(vaultCipher.getKeyPair()).thenReturn(new KeyPair(publicKey, privateKey));

    keyAwareCipher.register(userId);
    keyAwareCipher.revoke(userId);

    Optional<PublicKey> publicKey = keyAwareCipher.publicKey(userId);

    assertThat(publicKey).isNotPresent();
  }
}
