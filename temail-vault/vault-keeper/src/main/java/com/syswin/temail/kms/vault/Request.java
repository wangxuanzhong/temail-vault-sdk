package com.syswin.temail.kms.vault;

import java.util.Objects;

class Request {

  private final String token;
  // TODO: 2018/9/21 weird naming
  private final String text;
  private final String algorithm;

  Request(String tenantId, String userId, CipherAlgorithm algorithm) {
    this.token = tenantId;
    this.text = userId;
    this.algorithm = algorithm.name();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Request request = (Request) o;
    return Objects.equals(token, request.token) &&
        Objects.equals(text, request.text) &&
        Objects.equals(algorithm, request.algorithm);
  }

  @Override
  public int hashCode() {
    return Objects.hash(token, text, algorithm);
  }
}
