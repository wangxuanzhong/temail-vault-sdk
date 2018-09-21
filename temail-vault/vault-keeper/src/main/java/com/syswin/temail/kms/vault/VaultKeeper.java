package com.syswin.temail.kms.vault;

import static java.util.Arrays.asList;

import com.syswin.temail.kms.vault.cache.DefaultCache;
import com.syswin.temail.kms.vault.cache.ICache;
import com.syswin.temail.kms.vault.infrastructure.HttpClientRestClient;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class VaultKeeper {

  private final Map<CipherAlgorithm, KeyAwareAsymmetricCipher> asymmetricCiphers;

  public VaultKeeper(String kmsBaseUrl, String tenantId, ICache iCache) {
    this(kmsBaseUrl, tenantId, iCache, new NativeAsymmetricCipher());
  }

  public VaultKeeper(String kmsBaseUrl, String tenantId) {
    this(kmsBaseUrl, tenantId, new DefaultCache());
  }

  private VaultKeeper(String baseUrl, String tenantId, ICache iCache, AsymmetricCipher cipher) {
    this(asList(new DelegatingKeyAwareAsymmetricCipher(
        cipher,
        new RemoteKeyRegistry(iCache, new HttpClientRestClient(baseUrl), cipher.algorithm()))));
  }

  VaultKeeper(Collection<KeyAwareAsymmetricCipher> asymmetricCiphers) {
    this.asymmetricCiphers = new ConcurrentHashMap<>();
    asymmetricCiphers.forEach(cipher -> this.asymmetricCiphers.put(cipher.algorithm(), cipher));
  }

  public KeyAwareAsymmetricCipher asymmetricCipher(CipherAlgorithm algorithm) {
    return asymmetricCiphers.get(algorithm);
  }
}
