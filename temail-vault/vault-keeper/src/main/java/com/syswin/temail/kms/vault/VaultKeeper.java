package com.syswin.temail.kms.vault;

import static java.util.Arrays.asList;

import com.syswin.temail.kms.vault.cache.DefaultCache;
import com.syswin.temail.kms.vault.cache.ICache;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class VaultKeeper {

  private final Map<CipherAlgorithm, KeyAwareAsymmetricCipher> asymmetricCiphers;

  public VaultKeeper(String tenantId, ICache iCache) {
    this(asList(new DelegatingKeyAwareAsymmetricCipher(new NativeAsymmetricCipher(), iCache)));
  }

  public VaultKeeper(String tenantId) {
    this(tenantId, new DefaultCache());
  }

  VaultKeeper(Collection<KeyAwareAsymmetricCipher> asymmetricCiphers) {
    this.asymmetricCiphers = new ConcurrentHashMap<>();
    asymmetricCiphers.forEach(cipher -> this.asymmetricCiphers.put(cipher.algorithm(), cipher));
  }

  public KeyAwareAsymmetricCipher asymmetricCipher(CipherAlgorithm algorithm) {
    return asymmetricCiphers.get(algorithm);
  }

}
