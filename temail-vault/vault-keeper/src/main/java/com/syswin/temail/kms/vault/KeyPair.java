package com.syswin.temail.kms.vault;

public class KeyPair implements java.io.Serializable {

  private byte[] privateKey;
  private byte[] publicKey;

  public KeyPair(byte[] privateKey, byte[] publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  public byte[] getPrivate() {
    return privateKey;
  }

  public byte[] getPublic() {
    return publicKey;
  }
}
