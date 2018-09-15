package com.syswin.temail.kms.vault;

import static com.syswin.temail.kms.vault.CipherAlgorithm.SM2;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collections;
import org.junit.Test;
import org.mockito.Mockito;

public class VaultKeeperTest {
  private final KeyAwareAsymmetricCipher cipher = Mockito.mock(KeyAwareAsymmetricCipher.class);

  private final VaultKeeper vaultKeeper = new VaultKeeper(Collections.singletonList(cipher));

  @Test
  public void shouldUseSM2Cipher() {
    KeyAwareAsymmetricCipher asymmetricCipher = vaultKeeper.asymmetricCipher(SM2);
    assertThat(asymmetricCipher).isEqualTo(cipher);
  }
}
