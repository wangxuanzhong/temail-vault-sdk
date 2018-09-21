package com.syswin.temail.kms.vault;

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.util.Optional;

public class DelegatingKeyAwareAsymmetricCipher implements KeyAwareAsymmetricCipher {

  private final AsymmetricCipher cipher;
  private final KeyRegistry keyRegistry;

  DelegatingKeyAwareAsymmetricCipher(AsymmetricCipher cipher, KeyRegistry keyRegistry) {
    this.cipher = cipher;
    this.keyRegistry = keyRegistry;
  }

  @Override
  public String register(String userId) {
    KeyPair keyPair = keyRegistry.register(userId);
    return keyPair.getPublic();
  }

  @Override
  public Optional<String> publicKey(String userId) {
    KeyPair keyPair = keyRegistry.retrieve(userId);
    if (keyPair == null) {
      return Optional.empty();
    }
    return Optional.of(keyPair.getPublic());
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
    keyRegistry.remove(userId);
  }

  @Override
  public CipherAlgorithm algorithm() {
    return cipher.algorithm();
  }

  private KeyPair keyPair(String userId) {
    KeyPair keyPair = keyRegistry.retrieve(userId);
    if (keyPair == null) {
      throw new VaultCipherException("No such user registered: " + userId);
    }
    return keyPair;
  }
}
