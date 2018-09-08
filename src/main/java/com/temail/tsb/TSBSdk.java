package com.temail.tsb;

/**
 * Create by juzenhon on 2018/9/7
 *
 * @author: zhuxinhong
 */
public final class TSBSdk {

  static {
    System.loadLibrary("TSBJni");
    System.loadLibrary("tsb");
  }


  public interface KeyCallback {

    int onResult(String tid, int code, String key);
  }

  public static native boolean initTSBSDK(String tid, int type);

  public static native void setTSBSDKFolder(String path);

  public static native void setKeyCallback(KeyCallback callback);

  public static native void destroyTSBSDK(String tid);

  public static native byte[] getPublicKey(String tid);

  public static native byte[] encryptData(int type, byte[] key, byte[] plainText);

  public static native byte[] decryptData(int type, byte[] key, byte[] secData);

  public static native byte[] signature(byte[] context);

  public static native boolean verifySignature(byte[] context, byte[] signed);

}
