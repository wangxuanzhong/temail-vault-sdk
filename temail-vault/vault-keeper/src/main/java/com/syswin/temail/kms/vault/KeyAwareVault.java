package com.syswin.temail.kms.vault;

public interface KeyAwareVault extends Vault {

  KeyAwareAsymmetricCipher asymmetricCipher(CipherAlgorithm algorithm);

}
