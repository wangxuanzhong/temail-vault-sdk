package com.syswin.temail.kms.vault.cache;

import java.lang.invoke.MethodHandles;
import org.ehcache.CacheManager;
import org.ehcache.config.builders.CacheManagerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EhCacheConfig {
  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private final CacheManager cacheManager;

  private static final class SingletonHelper {
    private static final EhCacheConfig INSTANCE = new EhCacheConfig();
  }

  static EhCacheConfig getInstance() {
    return SingletonHelper.INSTANCE;
  }

  private EhCacheConfig() {
    cacheManager = CacheManagerBuilder
        .newCacheManagerBuilder()
        .build();

    cacheManager.init();
    Runtime.getRuntime().addShutdownHook(new Thread(this::close));
  }

  CacheManager cacheManager() {
    return cacheManager;
  }

  private void close() {
    try {
      cacheManager.close();
    } catch (Exception e) {
      LOG.warn("Failed to close cache manager", e);
    }
  }
}
