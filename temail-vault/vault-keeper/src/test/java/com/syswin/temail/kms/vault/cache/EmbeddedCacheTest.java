package com.syswin.temail.kms.vault.cache;

import static com.seanyinx.github.unit.scaffolding.Randomness.uniquify;
import static org.assertj.core.api.Assertions.assertThat;

import com.syswin.temail.kms.vault.KeyPair;
import org.junit.Test;

public class EmbeddedCacheTest {

  private final String userId = uniquify("user id");
  private final String privateKey = uniquify("public key");
  private final String publicKey = uniquify("private key");
  private final KeyPair keyPair = new KeyPair(privateKey.getBytes(), publicKey.getBytes());

  private final ICache cache = new EmbeddedCache(10);

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
}
