package com.syswin.temail.kms.vault;

public interface KeyAwareAsymmetricVaultKeeper extends AsymmetricVaultKeeper {

  KeyAwareAsymmetricCipher asymmetricCipher(CipherAlgorithm algorithm);

}
