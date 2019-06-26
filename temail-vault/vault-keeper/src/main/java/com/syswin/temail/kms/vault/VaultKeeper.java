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

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;

import com.syswin.temail.kms.vault.aes.SymmetricCipher;
import com.syswin.temail.kms.vault.cache.EmbeddedCache;
import com.syswin.temail.kms.vault.cache.ICache;
import com.syswin.temail.kms.vault.infrastructure.HttpClientRestClient;
import java.lang.invoke.MethodHandles;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.ServiceLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class VaultKeeper implements KeyAwareVault {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private static final int DEFAULT_CACHE_ENTRIES = 1000;
  static final String KEY_VAULT_CACHE_ENTRIES = "app.vault.cache.entries";

  private final Map<CipherAlgorithm, KeyAwareAsymmetricCipher> keyAwareAsymmetricCiphers;
  private final Map<CipherAlgorithm, AsymmetricCipher> asymmetricCiphers;
  private final SymmetricCipher symmetricCipher;

  public static KeyAwareVault keyAwareVault(String kmsBaseUrl, String tenantId) {
    return new VaultKeeper(kmsBaseUrl, tenantId);
  }

  public static Vault vault() {
    return new VaultKeeper(emptyList(), asList(new NativeAsymmetricCipher()));
  }

  private VaultKeeper(String kmsBaseUrl, String tenantId) {
    this(kmsBaseUrl, tenantId, new EmbeddedCache(entries()), new NativeAsymmetricCipher());
  }

  private VaultKeeper(String baseUrl, String tenantId, ICache iCache, AsymmetricCipher cipher) {
    this(asList(new DelegatingKeyAwareAsymmetricCipher(
            tenantId,
            cipher,
            new RemoteKeyRegistry(iCache, new HttpClientRestClient(baseUrl), cipher.algorithm()))),
        asList(cipher));
  }

  VaultKeeper(Collection<KeyAwareAsymmetricCipher> keyAwareAsymmetricCiphers, Collection<AsymmetricCipher> asymmetricCiphers) {
    this.keyAwareAsymmetricCiphers = new HashMap<>();
    keyAwareAsymmetricCiphers.forEach(cipher -> this.keyAwareAsymmetricCiphers.put(cipher.algorithm(), cipher));

    this.asymmetricCiphers = new HashMap<>();
    asymmetricCiphers.forEach(cipher -> this.asymmetricCiphers.put(cipher.algorithm(), cipher));

    Iterator<SymmetricCipher> iterator = ServiceLoader.load(SymmetricCipher.class).iterator();
    if (iterator.hasNext()) {
      this.symmetricCipher = iterator.next();
    } else {
      this.symmetricCipher = new NullSymmetricCipher();
    }
  }

  @Override
  public KeyAwareAsymmetricCipher asymmetricCipher(CipherAlgorithm algorithm) {
    return keyAwareAsymmetricCiphers.get(algorithm);
  }

  @Override
  public PublicKeyCipher publicKeyCipher(CipherAlgorithm algorithm) {
    return asymmetricCiphers.get(algorithm);
  }

  @Override
  public SymmetricCipher symmetricCipher() {
    return symmetricCipher;
  }

  @Override
  public AsymmetricCipher plainAsymmetricCipher(CipherAlgorithm algorithm) {
    return asymmetricCiphers.get(algorithm);
  }

  private static int entries() {
    String entries = System.getProperty(KEY_VAULT_CACHE_ENTRIES);
    if (entries == null) {
      LOG.info("No configured key cache entries and setting default cache entries to {}", DEFAULT_CACHE_ENTRIES);
      return DEFAULT_CACHE_ENTRIES;
    }
    try {
      return Integer.parseInt(entries);
    } catch (NumberFormatException e) {
      LOG.warn("Failed to parse configured key cache entries {} and setting default cache entries to {}", entries, DEFAULT_CACHE_ENTRIES, e);
      return DEFAULT_CACHE_ENTRIES;
    }
  }
}
