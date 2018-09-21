package com.syswin.temail.kms.vault;

import static java.util.Arrays.asList;

import com.syswin.temail.kms.vault.cache.DefaultCache;
import com.syswin.temail.kms.vault.cache.ICache;
import com.syswin.temail.kms.vault.infrastructure.HttpClientRestClient;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class VaultKeeper {

  private static final String KEY_REGISTRY_URL = "temail.vault.registry.url";
  private final Map<CipherAlgorithm, KeyAwareAsymmetricCipher> asymmetricCiphers;

  public VaultKeeper(String tenantId, ICache iCache) {
    this(tenantId, iCache, new NativeAsymmetricCipher());
  }

  public VaultKeeper(String tenantId) {
    this(tenantId, new DefaultCache());
  }

  private VaultKeeper(String tenantId, ICache iCache, AsymmetricCipher cipher) {
    this(asList(new DelegatingKeyAwareAsymmetricCipher(
        cipher,
        new RemoteKeyRegistry(iCache, new HttpClientRestClient(baseUrl()), cipher.algorithm()))));
  }

  VaultKeeper(Collection<KeyAwareAsymmetricCipher> asymmetricCiphers) {
    this.asymmetricCiphers = new ConcurrentHashMap<>();
    asymmetricCiphers.forEach(cipher -> this.asymmetricCiphers.put(cipher.algorithm(), cipher));
  }

  public KeyAwareAsymmetricCipher asymmetricCipher(CipherAlgorithm algorithm) {
    return asymmetricCiphers.get(algorithm);
  }

  private static String baseUrl() {
    String property = System.getProperty(KEY_REGISTRY_URL);
    if (property == null) {
      throw new IllegalArgumentException("Key registry url is not provided at: " + KEY_REGISTRY_URL);
    }
    return property;
  }
}
