package com.syswin.temail.kms.vault;

import java.util.Objects;

public class Request {

  private final String userId;
  private final String algorithm;

  public Request(String userId, CipherAlgorithm algorithm) {
    this.userId = userId;
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
    return Objects.equals(userId, request.userId) &&
        Objects.equals(algorithm, request.algorithm);
  }

  @Override
  public int hashCode() {
    return Objects.hash(userId, algorithm);
  }
}
