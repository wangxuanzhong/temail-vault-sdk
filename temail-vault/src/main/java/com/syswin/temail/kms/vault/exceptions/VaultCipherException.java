package com.syswin.temail.kms.vault.exceptions;

public class VaultCipherException extends RuntimeException {

  public VaultCipherException() {
  }

  public VaultCipherException(String message) {
    super(message);
  }

  public VaultCipherException(String message, Throwable cause) {
    super(message, cause);
  }

  public VaultCipherException(Throwable cause) {
    super(cause);
  }

  public VaultCipherException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

}
