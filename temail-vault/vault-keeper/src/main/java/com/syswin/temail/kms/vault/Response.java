package com.syswin.temail.kms.vault;

public class Response {

  private Integer code;
  private String message;
  private KeyPair keyPair;

  Response() {
  }

  public Response(Integer code, String message, KeyPair keyPair) {
    this.code = code;
    this.message = message;
    this.keyPair = keyPair;
  }

  public Integer getCode() {
    return code;
  }

  public String getMessage() {
    return message;
  }

  public KeyPair getKeyPair() {
    return keyPair;
  }
}
