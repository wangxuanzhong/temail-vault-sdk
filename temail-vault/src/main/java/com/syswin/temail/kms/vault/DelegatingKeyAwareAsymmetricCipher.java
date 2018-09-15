package com.syswin.temail.kms.vault;

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class DelegatingKeyAwareAsymmetricCipher implements KeyAwareAsymmetricCipher {

  private final AsymmetricCipher cipher;
  private final Map<String, KeyPair> userKeys = new ConcurrentHashMap<>();

  DelegatingKeyAwareAsymmetricCipher(AsymmetricCipher cipher) {
    this.cipher = cipher;
  }

  @Override
  public PublicKey register(String userId) {
    return userKeys.computeIfAbsent(userId, k -> cipher.getKeyPair())
        .getPublic();
  }

  @Override
  public Optional<PublicKey> publicKey(String userId) {
    KeyPair keyPair = userKeys.get(userId);
    if (keyPair == null) {
      return Optional.empty();
    }
    return Optional.of(keyPair.getPublic());
  }

  @Override
  public byte[] encrypt(String userId, String plaintext) throws Exception {
    return cipher.encrypt(keyPair(userId).getPublic(), plaintext);
  }

  @Override
  public String decrypt(String userId, byte[] encryptedBytes) throws Exception {
    return cipher.decrypt(keyPair(userId).getPrivate(), encryptedBytes);
  }

  @Override
  public byte[] sign(String userId, byte[] unsigned) throws Exception {
    return cipher.sign(keyPair(userId).getPrivate(), unsigned);
  }

  @Override
  public boolean verify(String userId, byte[] unsigned, byte[] signed) {
    return cipher.verify(keyPair(userId).getPublic(), unsigned, signed);
  }

  @Override
  public void revoke(String userId) {
    userKeys.remove(userId);
  }

  @Override
  public CipherAlgorithm algorithm() {
    return cipher.algorithm();
  }

  private KeyPair keyPair(String userId) {
    KeyPair keyPair = userKeys.get(userId);
    if (keyPair == null) {
      throw new VaultCipherException("No such user registered: " + userId);
    }
    return keyPair;
  }
}
