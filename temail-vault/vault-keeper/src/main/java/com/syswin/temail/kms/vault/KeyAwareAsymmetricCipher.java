package com.syswin.temail.kms.vault;

import java.util.Optional;

public interface KeyAwareAsymmetricCipher extends KeyAwareCipher {

  byte[] register(String userId);

  Optional<byte[]> publicKey(String userId);
}
