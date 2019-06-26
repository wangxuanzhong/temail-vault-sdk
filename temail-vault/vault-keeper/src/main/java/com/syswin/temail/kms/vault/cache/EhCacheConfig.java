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
