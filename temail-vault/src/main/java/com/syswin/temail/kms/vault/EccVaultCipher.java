package com.syswin.temail.kms.vault;

import static java.nio.charset.StandardCharsets.UTF_8;
import static sun.security.x509.CertificateAlgorithmId.ALGORITHM;

import java.lang.invoke.MethodHandles;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EccVaultCipher implements VaultCipher {
  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  public static final String EC = "EC";
  public static final String PARAMS = "secp256r1";
  public static final String SHA_256_WITH_ECDSA = "SHA256withECDSA";

  private final Signature signature;
  private final KeyFactory factory;

  public EccVaultCipher() {
    try {
      signature = Signature.getInstance(SHA_256_WITH_ECDSA);
      factory = KeyFactory.getInstance(EC);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public KeyPair getKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EC);
    keyGen.initialize(new ECGenParameterSpec(PARAMS));
    return keyGen.generateKeyPair();
  }

  // TODO: 2018/9/13 copied from TAIP proxy project and test cases / refactoring is in order
  @Override
  public byte[] encrypt(PublicKey privateKey, String plaintext)
      throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {

    Cipher c1 = Cipher.getInstance(ALGORITHM);
    c1.init(Cipher.ENCRYPT_MODE, privateKey);
    return c1.doFinal(plaintext.getBytes(UTF_8));
  }

  @Override
  public String decrypt(PrivateKey shareKey, byte[] encryptedBytes) throws Exception {
    Cipher c1 = Cipher.getInstance(ALGORITHM);
    c1.init(Cipher.DECRYPT_MODE, shareKey);
    byte[] output = c1.doFinal(encryptedBytes);
    return new String(output, UTF_8);
  }

  @Override
  public byte[] sign(PrivateKey privateKey, byte[] unsigned) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature signature = Signature.getInstance(SHA_256_WITH_ECDSA);
    signature.initSign(privateKey);
    signature.update(unsigned);
    return signature.sign();
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
}
