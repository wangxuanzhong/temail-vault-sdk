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

package com.syswin.temail.kms.vault.infrastructure;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.http.HttpHost;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpClientConfig {
  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private final PoolingHttpClientConnectionManager connManager;
  private final Map<String, CloseableHttpClient> clients = new ConcurrentHashMap<>();

  private static final class SingletonHelper {
    private static final HttpClientConfig INSTANCE = new HttpClientConfig();
  }

  static HttpClientConfig getInstance() {
    return SingletonHelper.INSTANCE;
  }

  private HttpClientConfig() {
    connManager = new PoolingHttpClientConnectionManager();
    connManager.setMaxTotal(20);
    connManager.setDefaultMaxPerRoute(5);

    Runtime.getRuntime().addShutdownHook(new Thread(this::close));
  }

  CloseableHttpClient httpClient(String baseUrl) {
    connManager.setMaxPerRoute(new HttpRoute(new HttpHost(baseUrl)), 5);

    return clients.computeIfAbsent(baseUrl, url -> HttpClients.custom()
        .setConnectionManager(connManager)
        .build());
  }

  private void close() {
    try {
      clients.values().forEach(client -> {
        try {
          client.close();
        } catch (IOException e) {
          LOG.warn("Failed to close http client", e);
        }
      });

      connManager.close();
    } catch (Exception e) {
      LOG.warn("Failed to close http client connection manager", e);
    }
  }
}
