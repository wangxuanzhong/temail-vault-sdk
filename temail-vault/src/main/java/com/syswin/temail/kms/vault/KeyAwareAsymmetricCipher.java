package com.syswin.temail.kms.vault;

import java.security.PublicKey;
import java.util.Optional;

public interface KeyAwareAsymmetricCipher extends KeyAwareCipher {

  PublicKey register(String userId);

  Optional<PublicKey> publicKey(String userId);
}
