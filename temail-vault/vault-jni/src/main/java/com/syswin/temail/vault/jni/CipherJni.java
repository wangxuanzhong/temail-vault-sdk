package com.syswin.temail.vault.jni;

import java.io.IOException;

public class CipherJni {

  static {

    try {
      try {
        final NativeUtils nativeUtils = new NativeUtils("vault");
        nativeUtils.extractLibraryFromJar("/native/libecc.a");
        nativeUtils.extractLibraryFromJar("/libcrypto.a");
        nativeUtils.extractLibraryFromJar("/libssl.a");
        nativeUtils.loadLibraryFromJar("/native/libVault.so");
      } catch (IOException e) {
        throw new IllegalStateException("Failed to load native library", e);
      }
    } catch (Throwable e) {
      // TODO 兼容windows版本开发使用
      if (System.getProperty("os.name").contains("Windows")) {
        e.printStackTrace();
      } else {
        throw e;
      }
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
