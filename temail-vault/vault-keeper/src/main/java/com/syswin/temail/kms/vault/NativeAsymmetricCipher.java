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

import static com.syswin.temail.kms.vault.CipherAlgorithm.ECDSA;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.syswin.temail.vault.jni.CipherJni;
import java.lang.invoke.MethodHandles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class NativeAsymmetricCipher implements AsymmetricCipher {
  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private final CipherJni cipher;

  NativeAsymmetricCipher() {
    cipher = new CipherJni();
  }

  @Override
  public KeyPair getKeyPair() {
    CipherJni.KeyPair keyPair = cipher.generateKeyPair();
    KeyPair result = new KeyPair(keyPair.privateKey(), keyPair.publicKey());
    LOG.debug("Generated key pair with public key [{}]", result.getPublic());
    return result;
  }

  @Override
  public String encrypt(String publicKey, String plaintext) {
    LOG.debug("Encrypting plaintext with public key [{}]", publicKey);
    final String encrypted = new String(cipher.encrypt(publicKey.getBytes(), plaintext));
    LOG.debug("Encrypted plaintext with public key [{}] to [{}]", publicKey, encrypted);
    return encrypted;
  }

  @Override
  public String decrypt(String privateKey, String encrypted) {
    LOG.debug("Decrypting secret text [{}]", encrypted);
    final String plaintext = new String(cipher.decrypt(privateKey.getBytes(), encrypted.getBytes()), UTF_8);
    LOG.debug("Decrypted secret text [{}]", encrypted);
    return plaintext;
  }

  @Override
  public String sign(String privateKey, String plaintext) {
    LOG.debug("Signing plaintext [{}]", plaintext);
    final String signature = new String(cipher.sign(privateKey.getBytes(), plaintext), UTF_8);
    LOG.debug("Signed plaintext [{}] with signature [{}]", plaintext, signature);
    return signature;
  }

  @Override
  public boolean verify(String publicKey, String plaintext, String signature) {
    try {
      LOG.debug("Verified signature [{}] with plaintext [{}]", signature, plaintext);
      return cipher.verify(publicKey.getBytes(), plaintext, signature.getBytes());
    } catch (Exception e) {
      LOG.warn("Failed to verify signature of [{}]", plaintext, e);
      return false;
    }
  }

  @Override
  public CipherAlgorithm algorithm() {
    return ECDSA;
  }
}
