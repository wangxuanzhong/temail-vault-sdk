package com.syswin.temail.vault.sdk;

import com.temail.tsb.TSBSdk;
import java.util.function.Supplier;

public class VaultSdk {

  private static final String key = "secret";

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

  private static final class SingletonHelper {

    private static final VaultSdk INSTANCE = new VaultSdk();
  }

  public static VaultSdk getInstance() {
    return SingletonHelper.INSTANCE;
  }

  private VaultSdk() {
  }

  public void withBackupDir(String backupDir) {
    TSBSdk.setTSBSDKFolder(backupDir);

    // TODO: 2018/9/7 set up password per temail?
    /*TSBSdk.setKeyCallback(new KeyCallback() {
      @Override
      public long onResult(String tid, long code, String key) {
        key = "123456";
        return 0;
      }
    });*/
  }

  public byte[] generatePublicKey(Algorithm algorithm, String temail) {
    return supplyWith(algorithm, temail, () -> TSBSdk.getPublicKey(temail));
  }

  public byte[] encrypt(Algorithm algorithm, String temail, String text) {
    return supplyWith(algorithm, temail, () -> TSBSdk.encryptData(algorithm.code(), key.getBytes(), text.getBytes()));
  }

  public byte[] decrypt(Algorithm algorithm, String temail, byte[] encrypted) {
    return supplyWith(algorithm, temail, () -> TSBSdk.decryptData(algorithm.code(), key.getBytes(), encrypted));
  }

  public byte[] sign(Algorithm algorithm, String temail, String text) {
    return supplyWith(algorithm, temail, () -> TSBSdk.signature(text.getBytes()));
  }

  public boolean verify(Algorithm algorithm, String temail, String text, byte[] signature) {
    return supplyWith(algorithm, temail, () -> TSBSdk.verifySignature(text.getBytes(), signature));
  }

  private boolean open(String temail, Algorithm algorithm) {
    return TSBSdk.initTSBSDK(temail, algorithm.code());
  }

  private void close(String temail) {
    TSBSdk.destroyTSBSDK(temail);
  }

  private <T> T supplyWith(Algorithm algorithm, String temail, Supplier<T> supplier) {
    synchronized (this) {
      if (open(temail, algorithm)) {
        final T result = supplier.get();
        close(temail);
        return result;
      }
    }

    throw new VaultSdkException("Failed to initialize TSB SDK");
  }

  static class VaultSdkException extends RuntimeException {

    VaultSdkException(String message) {
      super(message);
    }
  }
}
