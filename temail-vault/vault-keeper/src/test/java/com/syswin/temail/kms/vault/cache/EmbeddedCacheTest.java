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

package com.syswin.temail.kms.vault.cache;

import static com.seanyinx.github.unit.scaffolding.Randomness.uniquify;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.waitAtMost;

import com.syswin.temail.kms.vault.KeyPair;
import org.junit.Test;

public class EmbeddedCacheTest {

  private final String userId = uniquify("user id");
  private final String privateKey = uniquify("public key");
  private final String publicKey = uniquify("private key");
  private final KeyPair keyPair = new KeyPair(privateKey.getBytes(), publicKey.getBytes());

  private final ICache cache = new EmbeddedCache(10, 1L);

  @Test
  public void shouldGetValueAfterSaving() {
    cache.put(userId, keyPair);

    KeyPair value = cache.get(userId);

    assertThat(value).isEqualToComparingFieldByField(this.keyPair);
  }

  @Test
  public void shouldGetNothingIfNotSaved() {
    assertThat(cache.get(userId)).isNull();
  }

  @Test
  public void shouldRemoveExistingKey() {
    cache.put(userId, keyPair);
    assertThat(cache.get(userId)).isNotNull();

    cache.remove(userId);
    assertThat(cache.get(userId)).isNull();
  }

  @Test
  public void shouldExpireExistingKey() {
    cache.put(userId, keyPair);
    assertThat(cache.get(userId)).isNotNull();

    waitAtMost(2, SECONDS).untilAsserted(
        () -> assertThat(cache.get(userId)).isNull());
  }
}
