package com.syswin.temail.kms.vault;

import static com.syswin.temail.kms.vault.CipherAlgorithm.ECDSA;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.syswin.temail.vault.jni.CipherJni;
import java.lang.invoke.MethodHandles;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class NativeAsymmetricCipher implements AsymmetricCipher {
  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private final CipherJni cipher;

  NativeAsymmetricCipher() {
    cipher = new CipherJni();
  }

  @Override
  public KeyPair getKeyPair() {
    CipherJni.KeyPair keyPair = cipher.generateKeyPair();
    return new KeyPair(keyPair.privateKey(), keyPair.publicKey());
  }

  @Override
  public String encrypt(String publicKey, String plaintext) {
    // TODO: 2018/9/20 all others are base64 encoded by C++ except encrypted bytes
    return Base64.getEncoder().encodeToString(cipher.encrypt(publicKey.getBytes(), plaintext));
  }

  @Override
  public String decrypt(String privateKey, String encrypted) {
    return new String(cipher.decrypt(privateKey.getBytes(), Base64.getDecoder().decode(encrypted)), UTF_8);
  }

  @Override
  public String sign(String privateKey, String plaintext) {
    return new String(cipher.sign(privateKey.getBytes(), plaintext), UTF_8);
  }

  @Override
  public boolean verify(String publicKey, String plaintext, String signature) {
    try {
      return cipher.verify(publicKey.getBytes(), plaintext, signature.getBytes());
    } catch (Exception e) {
      LOG.error("Failed to verify signature of [{}]", plaintext, e);
      return false;
    }
  }

  @Override
  public CipherAlgorithm algorithm() {
    return ECDSA;
  }
}
