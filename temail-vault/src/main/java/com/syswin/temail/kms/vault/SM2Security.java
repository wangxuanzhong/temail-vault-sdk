package com.syswin.temail.kms.vault;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.bouncycastle.math.ec.ECConstants.ONE;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SM2Security implements Security {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private static final String EC = "EC";
  private static final String BC = "BC";

  private final Signature signature;
  private final KeyFactory factory;
  private static final BigInteger GX = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
  private static final BigInteger GY = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
  private static final BigInteger N = new BigInteger("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123", 16);
  private static final BigInteger P = new BigInteger("fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", 16);
  private static final BigInteger A = new BigInteger("fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc", 16);
  private static final BigInteger B = new BigInteger("28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93", 16);
  private final KeyPairGenerator keyPairGenerator;
  private final ECParameterSpec parameterSpec;

  public SM2Security() {
    try {
      java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

      signature = Signature.getInstance("SM3withSM2");
      factory = KeyFactory.getInstance(EC, BC);

      ECCurve curve = new ECCurve.Fp(P, A, B, N, ONE);
      ECPoint g = curve.createPoint(GX, GY);

      keyPairGenerator = KeyPairGenerator.getInstance(EC, BC);
      parameterSpec = new ECParameterSpec(curve, g, N);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public KeyPair getKeyPair() throws Exception {
    keyPairGenerator.initialize(parameterSpec, new SecureRandom());

    return keyPairGenerator.generateKeyPair();
  }

  @Override
  public byte[] encrypt(PublicKey publicKey, String plaintext) throws Exception {
    Cipher c1 = Cipher.getInstance("ECIES", BC);
    c1.init(Cipher.ENCRYPT_MODE, publicKey);
    return c1.doFinal(plaintext.getBytes(UTF_8));
  }

  @Override
  public String decrypt(PrivateKey privateKey, byte[] encryptedBytes) throws Exception {
    Cipher c1 = Cipher.getInstance("ECIES", BC);
    c1.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] output = c1.doFinal(encryptedBytes);
    return new String(output, UTF_8);
  }

  @Override
  public byte[] sign(PrivateKey privateKey, byte[] unsigned) throws Exception {
    signature.initSign(privateKey, new SecureRandom());
    signature.update(unsigned);
    return signature.sign();
  }

  @Override
  public boolean verify(byte[] publicKey, byte[] unsigned, byte[] signed) {
    try {
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
      PublicKey key = factory.generatePublic(keySpec);
      signature.initVerify(key);
      signature.update(unsigned);
      return signature.verify(signed);
    } catch (Exception e) {
      LOG.error("Failed to verify signature of {} with public key {}", unsigned, publicKey, e);
    }
    return false;
  }
}
