package com.syswin.temail.kms.vault;

import java.util.Objects;

public class Request {

  // TODO: 2018/9/21 weird naming
  private final String text;
  private final String algorithm;

  public Request(String userId, CipherAlgorithm algorithm) {
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
    return Objects.equals(text, request.text) &&
        Objects.equals(algorithm, request.algorithm);
  }

  @Override
  public int hashCode() {
    return Objects.hash(text, algorithm);
  }
}
