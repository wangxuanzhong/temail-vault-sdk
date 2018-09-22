package com.syswin.temail.kms.vault;

import java.util.Optional;

public class DelegatingKeyAwareAsymmetricCipher implements KeyAwareAsymmetricCipher {

  private final String tenantId;
  private final AsymmetricCipher cipher;
  private final KeyRegistry keyRegistry;

  DelegatingKeyAwareAsymmetricCipher(String tenantId, AsymmetricCipher cipher, KeyRegistry keyRegistry) {
    this.tenantId = tenantId;
    this.cipher = cipher;
    this.keyRegistry = keyRegistry;
  }

  @Override
  public String register(String userId) {
    KeyPair keyPair = keyRegistry.register(tenantId, userId);
    return keyPair.getPublic();
  }

  @Override
  public Optional<String> publicKey(String userId) {
    try {
      KeyPair keyPair = keyRegistry.retrieve(tenantId, userId);
      return Optional.of(keyPair.getPublic());
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  @Override
  public String encrypt(String userId, String plaintext) {
    return cipher.encrypt(keyPair(userId).getPublic(), plaintext);
  }

  @Override
  public String decrypt(String userId, String encryptedBytes) {
    return cipher.decrypt(keyPair(userId).getPrivate(), encryptedBytes);
  }

  @Override
  public String sign(String userId, String plaintext) {
    return cipher.sign(keyPair(userId).getPrivate(), plaintext);
  }

  @Override
  public boolean verify(String userId, String plaintext, String signed) {
    return cipher.verify(keyPair(userId).getPublic(), plaintext, signed);
  }

  @Override
  public void revoke(String userId) {
    keyRegistry.remove(tenantId, userId);
  }

  @Override
  public CipherAlgorithm algorithm() {
    return cipher.algorithm();
  }

  private KeyPair keyPair(String userId) {
    return keyRegistry.retrieve(tenantId, userId);
  }
}
