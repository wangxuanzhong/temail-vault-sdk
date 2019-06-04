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
