package com.syswin.temail.vault.sdk;

import static com.syswin.temail.vault.sdk.VaultSdk.Algorithm.ECC;

import java.util.Base64;

public class VaultSdkTest {
  public static void main(String[] args) {
    final VaultSdk vaultSdk = VaultSdk.getInstance();

    final String[] temails = {"sean@t.email", "jack@t.email"};

    for (String temail : temails) {
      vaultSdk.withBackupDir("/tmp");

      final byte[] pubKey = vaultSdk.generatePublicKey(ECC, temail);
      System.out.println("*****get public key******");
      System.out.println(encode(pubKey));
      byte[] encrypted = vaultSdk.encrypt(ECC, temail, temail);
      System.out.println("*****encryption******");
      System.out.println(encode(encrypted));

      System.out.println("*****decryption******");
      byte[] text = vaultSdk.decrypt(ECC, temail, encrypted);
      System.out.println(new String(text));

      final byte[] signature = vaultSdk.sign(ECC, temail, temail);
      System.out.println("*****sign******");
      System.out.println(encode(signature));
      final boolean verified = vaultSdk.verify(ECC, temail, temail, signature);
      System.out.println("*****verify******");
      System.out.println(verified);
    }
  }

  private static String encode(byte[] bytes) {
    if (bytes == null) {
      throw new IllegalStateException("Unable to encode empty bytes");
    }
    return Base64.getEncoder().encodeToString((bytes));
  }
}
