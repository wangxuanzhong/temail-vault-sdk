/*
 * MIT License
 *
 * Copyright (c) 2019 Syswin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
