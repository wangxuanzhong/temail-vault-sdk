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
