package com.syswin.temail.kms.vault;

import static com.syswin.temail.kms.vault.CipherAlgorithm.SM2;
import static com.syswin.temail.kms.vault.VaultKeeper.KEY_VAULT_CACHE_ENTRIES;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.Collections;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class VaultKeeperTest {
  private final KeyAwareAsymmetricCipher cipher = Mockito.mock(KeyAwareAsymmetricCipher.class);

  private VaultKeeper vaultKeeper;

  @Before
  public void setUp() {
    when(cipher.algorithm()).thenReturn(SM2);
    vaultKeeper = new VaultKeeper(Collections.singletonList(cipher));
  }

  @Test
  public void shouldUseSM2Cipher() {
    KeyAwareAsymmetricCipher asymmetricCipher = vaultKeeper.asymmetricCipher(SM2);
    assertThat(asymmetricCipher).isEqualTo(cipher);
  }

  @Test
  public void doesNotBlowIfSettingCacheEntriesWrong() {
    System.setProperty(KEY_VAULT_CACHE_ENTRIES, "x");
    vaultKeeper = new VaultKeeper(Collections.singletonList(cipher));
    System.clearProperty(KEY_VAULT_CACHE_ENTRIES);
  }
}
