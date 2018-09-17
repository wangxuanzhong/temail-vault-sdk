package com.syswin.temail.kms.vault;

import static java.nio.charset.StandardCharsets.UTF_8;
import static sun.security.x509.CertificateAlgorithmId.ALGORITHM;

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.lang.invoke.MethodHandles;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EccVaultCipher implements AsymmetricCipher {
  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  public static final String EC = "EC";
  public static final String PARAMS = "secp256r1";
  public static final String SHA_256_WITH_ECDSA = "SHA256withECDSA";

  private final Signature signature;

  public EccVaultCipher() {
    try {
      signature = Signature.getInstance(SHA_256_WITH_ECDSA);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public KeyPair getKeyPair() {
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EC);
      keyGen.initialize(new ECGenParameterSpec(PARAMS));
      return keyGen.generateKeyPair();
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      throw new IllegalStateException(e);
    }
  }

  // TODO: 2018/9/13 copied from TAIP proxy project and test cases / refactoring is in order
  @Override
  public byte[] encrypt(PublicKey privateKey, String plaintext) {

    try {
      Cipher c1 = Cipher.getInstance(ALGORITHM);
      c1.init(Cipher.ENCRYPT_MODE, privateKey);
      return c1.doFinal(plaintext.getBytes(UTF_8));
    } catch (Exception e) {
      throw new VaultCipherException("Failed in encryption", e);
    }
  }

  @Override
  public String decrypt(PrivateKey shareKey, byte[] encryptedBytes) {
    try {
      Cipher c1 = Cipher.getInstance(ALGORITHM);
      c1.init(Cipher.DECRYPT_MODE, shareKey);
      byte[] output = c1.doFinal(encryptedBytes);
      return new String(output, UTF_8);
    } catch (Exception e) {
      throw new VaultCipherException("Failed in decryption", e);
    }
  }

  @Override
  public byte[] sign(PrivateKey privateKey, byte[] unsigned) {
    try {
      Signature signature = Signature.getInstance(SHA_256_WITH_ECDSA);
      signature.initSign(privateKey);
      signature.update(unsigned);
      return signature.sign();
    } catch (Exception e) {
      throw new VaultCipherException("Failed in message signing", e);
    }
  }

  @Override
  public boolean verify(PublicKey publicKey, byte[] unsigned, byte[] signed) {
    try {
      signature.initVerify(publicKey);
      signature.update(unsigned);
      return signature.verify(signed);
    } catch (Exception e) {
      LOG.error("Failed to verify signature of {} with public key {}", unsigned, publicKey, e);
    }
    return false;
  }

  @Override
  public CipherAlgorithm algorithm() {
    return CipherAlgorithm.ECDSA;
  }
}
