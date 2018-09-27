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
    KeyPair result = new KeyPair(base64ToUrlSafe(keyPair.privateKey()), base64ToUrlSafe(keyPair.publicKey()));
    LOG.info("Generated key pair with public key [{}]", result.getPublic());
    return result;
  }

  @Override
  public String encrypt(String publicKey, String plaintext) {
    LOG.debug("Encrypting plaintext with public key [{}]", publicKey);
    // TODO: 2018/9/20 all others are base64UrlSafe encoded by C++ except encrypted bytes
    final String encrypted = encodeBase64UrlSafe(cipher.encrypt(base64ToUrlSafe(publicKey), plaintext));
    LOG.info("Encrypted plaintext with public key [{}] to [{}]", publicKey, encrypted);
    return encrypted;
  }

  @Override
  public String decrypt(String privateKey, String encrypted) {
    LOG.debug("Decrypting secret text [{}]", encrypted);
    final String plaintext = new String(cipher.decrypt(base64ToUrlSafe(privateKey), decodeBase64UrlSafe(encrypted)), UTF_8);
    LOG.info("Decrypted secret text [{}]", encrypted);
    return plaintext;
  }

  @Override
  public String sign(String privateKey, String plaintext) {
    LOG.debug("Signing plaintext [{}]", plaintext);
    final String signature = base64ToUrlSafe(cipher.sign(base64ToUrlSafe(privateKey), plaintext));
    LOG.info("Signed plaintext [{}] with signature [{}]", plaintext, signature);
    return signature;
  }

  @Override
  public boolean verify(String publicKey, String plaintext, String signature) {
    try {
      LOG.debug("Verified signature [{}] with plaintext [{}]", signature, plaintext);
      return cipher.verify(base64ToUrlSafe(publicKey), plaintext, base64ToUrlSafe(signature));
    } catch (Exception e) {
      LOG.error("Failed to verify signature of [{}]", plaintext, e);
      return false;
    }
  }

  @Override
  public CipherAlgorithm algorithm() {
    return ECDSA;
  }

  private String base64ToUrlSafe(byte[] bytes) {
    return Base64.getUrlEncoder()
        .encodeToString(Base64.getDecoder().decode(bytes));
  }

  private byte[] base64ToUrlSafe(String string) {
    return Base64.getEncoder()
        .encode(Base64.getUrlDecoder().decode(string));
  }

  private String encodeBase64UrlSafe(byte[] bytes) {
    return Base64.getUrlEncoder()
        .encodeToString(bytes);
  }

  private byte[] decodeBase64UrlSafe(String encrypted) {
    return Base64.getUrlDecoder().decode(encrypted);
  }
}
