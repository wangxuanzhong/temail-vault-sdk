package com.syswin.temail.kms.vault;

import com.syswin.temail.kms.vault.cache.ICache;
import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.util.Optional;

public class DelegatingKeyAwareAsymmetricCipher implements KeyAwareAsymmetricCipher {

  private final AsymmetricCipher cipher;
  private final ICache cache;

  DelegatingKeyAwareAsymmetricCipher(AsymmetricCipher cipher, ICache cache) {
    this.cipher = cipher;
    this.cache = cache;
  }

  @Override
  public byte[] register(String userId) {
    KeyPair keyPair = cipher.getKeyPair();
    cache.put(userId, keyPair);
    return keyPair.getPublic();
  }

  @Override
  public Optional<byte[]> publicKey(String userId) {
    KeyPair keyPair = cache.get(userId);
    if (keyPair == null) {
      return Optional.empty();
    }
    return Optional.of(keyPair.getPublic());
  }

  @Override
  public byte[] encrypt(String userId, String plaintext) {
    return cipher.encrypt(keyPair(userId).getPublic(), plaintext);
  }

  @Override
  public String decrypt(String userId, byte[] encryptedBytes) {
    return cipher.decrypt(keyPair(userId).getPrivate(), encryptedBytes);
  }

  @Override
  public byte[] sign(String userId, byte[] unsigned) {
    return cipher.sign(keyPair(userId).getPrivate(), unsigned);
  }

  @Override
  public boolean verify(String userId, byte[] unsigned, byte[] signed) {
    return cipher.verify(keyPair(userId).getPublic(), unsigned, signed);
  }

  @Override
  public void revoke(String userId) {
    cache.remove(userId);
  }

  @Override
  public CipherAlgorithm algorithm() {
    return cipher.algorithm();
  }

  private KeyPair keyPair(String userId) {
    KeyPair keyPair = cache.get(userId);
    if (keyPair == null) {
      throw new VaultCipherException("No such user registered: " + userId);
    }
    return keyPair;
  }
}
