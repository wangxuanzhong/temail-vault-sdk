package com.syswin.temail.vault.sdk;

import static com.syswin.temail.vault.sdk.VaultSdk.Algorithm.ECC;

import com.temail.tsb.TSBSdk;
import com.temail.tsb.TSBSdk.KeyCallback;
import java.util.Base64;

public class VaultSdk {

  public enum Algorithm {
    ECC (0),
    AES256CBC (1);

    private final int code;

    Algorithm(int code) {
      this.code = code;
    }

    public int code() {
      return code;
    }
  }

  public static void main(String[] args) {
    final String temail = "sean@t.email";
    final VaultSdk vaultSdk = new VaultSdk();
    final boolean opened = vaultSdk.open("/tmp", temail);
    System.out.println(opened);

    final String pubKey = vaultSdk.generateKeyPair(temail);
    System.out.println("*****get public key******");
    System.out.println(pubKey);
    String encrypted = vaultSdk.encrypt(ECC, "secret", temail);
    System.out.println("*****encryption******");
    System.out.println(encrypted);

    System.out.println("*****decryption******");
    String text = vaultSdk.decrypt(ECC, "secret", encrypted);
    System.out.println(text);

    assert temail.equals(text);

    final String signature = vaultSdk.sign(ECC, temail);
    System.out.println("*****sign******");
    System.out.println(signature);
    final boolean verified = vaultSdk.verify(ECC, temail, signature);
    System.out.println("*****verify******");
    System.out.println(verified);

    assert verified;

    vaultSdk.close(temail);
  }

  public boolean open(String backupDir, String temail) {
    TSBSdk.setTSBSDKFolder(backupDir);

    // TODO: 2018/9/7 set up password per temail?
    TSBSdk.setKeyCallback(new KeyCallback() {
      @Override
      public long onResult(String tid, long code, String key) {
        key = "123456";
        return 0;
      }
    });

    return TSBSdk.initTSBSDK(temail, ECC.code());
  }

  public void close(String temail) {
    TSBSdk.destroyTSBSDK(temail);
  }

  public String generateKeyPair(String temail) {
    return encode(TSBSdk.getPublicKey(temail));
  }

  public String encrypt(Algorithm algorithm, String key, String text) {
    return encode(TSBSdk.encryptData(algorithm.code(), key.getBytes(), text.getBytes()));
  }

  public String decrypt(Algorithm algorithm, String key, String encrypted) {
    return encode(TSBSdk.decryptData(algorithm.code(), key.getBytes(), Base64.getDecoder().decode(encrypted.getBytes())));
  }

  public String sign(Algorithm algorithm, String text) {
    return encode(TSBSdk.signature(text.getBytes()));
  }

  public boolean verify(Algorithm algorithm, String text, String signature) {
    return TSBSdk.verifySignature(text.getBytes(), signature.getBytes());
  }

  private String encode(byte[] bytes) {
    if (bytes == null) {
      throw new IllegalStateException("Unable to encode empty bytes");
    }
    return Base64.getEncoder().encodeToString((bytes));
  }
}
