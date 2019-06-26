/*
 * MIT License
 *
 * Copyright (c) 2019 Syswin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
