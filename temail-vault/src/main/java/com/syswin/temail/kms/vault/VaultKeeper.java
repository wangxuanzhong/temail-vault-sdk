package com.syswin.temail.kms.vault;

import static java.util.Arrays.asList;

import java.security.KeyPair;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class VaultKeeper {

  private final Map<CipherAlgorithm, KeyAwareAsymmetricCipher> asymmetricCiphers = new ConcurrentHashMap<>();

  public VaultKeeper() {
    this(asList(new DelegatingKeyAwareAsymmetricCipher(new SM2VaultCipher())));
  }

  VaultKeeper(Collection<KeyAwareAsymmetricCipher> asymmetricCiphers) {
    asymmetricCiphers.forEach(cipher -> this.asymmetricCiphers.put(cipher.algorithm(), cipher));
  }

  public KeyAwareAsymmetricCipher asymmetricCipher(CipherAlgorithm algorithm) {
    return asymmetricCiphers.get(algorithm);
  }

}
