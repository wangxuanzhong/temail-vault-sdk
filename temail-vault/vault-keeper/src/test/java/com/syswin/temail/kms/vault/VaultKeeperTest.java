package com.syswin.temail.kms.vault;

import static com.syswin.temail.kms.vault.CipherAlgorithm.ECDSA;
import static com.syswin.temail.kms.vault.VaultKeeper.KEY_VAULT_CACHE_ENTRIES;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class VaultKeeperTest {
  private final KeyAwareAsymmetricCipher keyAwareCipher = Mockito.mock(KeyAwareAsymmetricCipher.class);
  private final AsymmetricCipher cipher = Mockito.mock(AsymmetricCipher.class);

  private VaultKeeper vaultKeeper;

  @Before
  public void setUp() {
    when(keyAwareCipher.algorithm()).thenReturn(ECDSA);
    when(cipher.algorithm()).thenReturn(ECDSA);
    vaultKeeper = new VaultKeeper(singletonList(keyAwareCipher), singletonList(cipher));
  }

  @Test
  public void shouldUseSpecifiedCipher() {
    KeyAwareAsymmetricCipher keyAwareAsymmetricCipher = vaultKeeper.asymmetricCipher(ECDSA);
    assertThat(keyAwareAsymmetricCipher).isEqualTo(keyAwareCipher);

    PublicKeyCipher cipher = vaultKeeper.publicKeyCipher(ECDSA);
    assertThat(cipher).isEqualTo(this.cipher);

    AsymmetricCipher asymmetricCipher = vaultKeeper.plainAsymmetricCipher(ECDSA);
    assertThat(asymmetricCipher).isEqualTo(this.cipher);
  }

  @Test
  public void doesNotBlowIfSettingCacheEntriesWrong() {
    System.setProperty(KEY_VAULT_CACHE_ENTRIES, "x");
    vaultKeeper = new VaultKeeper(singletonList(keyAwareCipher), singletonList(cipher));
    System.clearProperty(KEY_VAULT_CACHE_ENTRIES);
  }
}
