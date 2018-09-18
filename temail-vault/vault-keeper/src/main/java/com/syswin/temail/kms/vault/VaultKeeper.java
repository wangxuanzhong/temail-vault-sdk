package com.syswin.temail.kms.vault;

import static java.util.Arrays.asList;

import com.syswin.temail.kms.vault.cache.DefaultCache;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class VaultKeeper {

  private final Map<CipherAlgorithm, KeyAwareAsymmetricCipher> asymmetricCiphers;

  public VaultKeeper() {
//    this(asList(new DelegatingKeyAwareAsymmetricCipher(new SM2VaultCipher())));
    this(asList(new DelegatingKeyAwareAsymmetricCipher(new AsymmetricCipher() {
      @Override
      public KeyPair getKeyPair() {
        return null;
      }

      @Override
      public byte[] encrypt(byte[] publicKey, String plaintext) {
        return new byte[0];
      }

      @Override
      public String decrypt(byte[] privateKey, byte[] encryptedBytes) {
        return null;
      }

      @Override
      public byte[] sign(byte[] privateKey, String plaintext) {
        return new byte[0];
      }

      @Override
      public boolean verify(byte[] publicKey, String plaintext, byte[] signature) {
        return false;
      }

      @Override
      public CipherAlgorithm algorithm() {
        return CipherAlgorithm.SM2;
      }
    }, new DefaultCache())));
  }

  VaultKeeper(Collection<KeyAwareAsymmetricCipher> asymmetricCiphers) {
    this.asymmetricCiphers = new ConcurrentHashMap<>();
    asymmetricCiphers.forEach(cipher -> this.asymmetricCiphers.put(cipher.algorithm(), cipher));
  }

  public KeyAwareAsymmetricCipher asymmetricCipher(CipherAlgorithm algorithm) {
    return asymmetricCiphers.get(algorithm);
  }

}
