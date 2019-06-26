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

package com.syswin.temail.vault.jni;

import java.io.IOException;

public class CipherJni {

  static {

    try {
      final NativeUtils nativeUtils = new NativeUtils("vault");
      nativeUtils.extractLibraryFromJar("/native/libecc.a");
      nativeUtils.extractLibraryFromJar("/libcrypto.a");
      nativeUtils.extractLibraryFromJar("/libssl.a");
      nativeUtils.loadLibraryFromJar("/native/libVault.so");
    } catch (IOException e) {
      throw new IllegalStateException("Failed to load native library", e);
    }
  }

  public static class KeyPair {

    private final byte[] publicKey;
    private final byte[] privateKey;

    public KeyPair(byte[] publicKey, byte[] privateKey) {
      this.publicKey = publicKey;
      this.privateKey = privateKey;
    }

    public byte[] publicKey() {
      return publicKey;
    }

    public byte[] privateKey() {
      return privateKey;
    }
  }

  public native KeyPair generateKeyPair();

  public native byte[] encrypt(byte[] publicKey, String plaintext);

  public native byte[] decrypt(byte[] privateKey, byte[] encrypted);

  public native byte[] sign(byte[] privateKey, String plaintext);

  public native boolean verify(byte[] publicKey, String plaintext, byte[] signature);

}
