package com.syswin.temail.kms.vault;

public interface AsymmetricVaultKeeper {

  PublicKeyCipher publicKeyCipher(CipherAlgorithm algorithm);
}
