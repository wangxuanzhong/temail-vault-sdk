package com.syswin.temail.kms.vault;

import com.syswin.temail.kms.vault.aes.SymmetricCipher;

public interface Vault {

  PublicKeyCipher publicKeyCipher(CipherAlgorithm algorithm);

  AsymmetricCipher plainAsymmetricCipher(CipherAlgorithm algorithm);

  SymmetricCipher symmetricCipher();
}
