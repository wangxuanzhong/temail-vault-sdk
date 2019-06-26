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

import static org.ehcache.expiry.ExpiryPolicy.NO_EXPIRY;

import com.syswin.temail.kms.vault.KeyPair;
import org.ehcache.Cache;
import org.ehcache.CacheManager;
import org.ehcache.config.CacheConfiguration;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.ResourcePoolsBuilder;

public class EmbeddedCache implements ICache {
  private static final String CACHE_NAME_PREFIX = "ehcache-vault-keypair-";
  private final CacheManager cacheManager;
  private final Cache<String, KeyPair> cache;

  public EmbeddedCache(int entries) {
    this.cacheManager = EhCacheConfig.getInstance().cacheManager();
    this.cache = createCache(CACHE_NAME_PREFIX + System.nanoTime(), entries);
  }

  private Cache<String, KeyPair> createCache(String cacheName, int entries) {
    CacheConfiguration<String, KeyPair> cacheConfiguration = CacheConfigurationBuilder
        .newCacheConfigurationBuilder(
            String.class,
            KeyPair.class,
            ResourcePoolsBuilder.heap(entries))
        .withExpiry(NO_EXPIRY)
        .build();

    return cacheManager.createCache(cacheName, cacheConfiguration);
  }


  @Override
  public KeyPair get(String key) {
    return cache.get(key);
  }

  @Override
  public void remove(String key) {
    cache.remove(key);
  }

  @Override
  public void put(String key, KeyPair value) {
    cache.put(key, value);
  }
}
