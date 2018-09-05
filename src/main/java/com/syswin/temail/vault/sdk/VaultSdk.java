package com.syswin.temail.vault.sdk;

import java.util.Base64;

public class VaultSdk {
  static {
    System.loadLibrary("VaultSdk");
    System.loadLibrary("tsb");
  }

  public static void main(String[] args) {
    final String publicKey = new VaultSdk().generateKeyPair("sean@t.email");
    System.out.println(Base64.getEncoder().encodeToString(publicKey.getBytes()));
  }

  public native String generateKeyPair(String temail);
}
