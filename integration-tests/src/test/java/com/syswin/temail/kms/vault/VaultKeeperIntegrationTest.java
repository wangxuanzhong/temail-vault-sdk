package com.syswin.temail.kms.vault;

import static com.syswin.temail.kms.vault.CipherAlgorithm.ECDSA;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.syswin.temail.kms.vault.aes.SymmetricCipher;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class VaultKeeperIntegrationTest {
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
  public void shouldUseProvidedSymmetricCipher() {
    SymmetricCipher symmetricCipher = vaultKeeper.symmetricCipher();

    assertThat(symmetricCipher).isInstanceOf(FakeSymmetricCipher.class);
  }
}
