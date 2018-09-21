package com.syswin.temail.kms.vault;

import static java.nio.charset.StandardCharsets.UTF_8;

public class KeyPair implements java.io.Serializable {

  private String privateKey;
  private String publicKey;

  public KeyPair(byte[] privateKey, byte[] publicKey) {
    this.privateKey = new String(privateKey, UTF_8);
    this.publicKey = new String(publicKey, UTF_8);
  }

  public String getPrivate() {
    return privateKey;
  }

  public String getPublic() {
    return publicKey;
  }
}
