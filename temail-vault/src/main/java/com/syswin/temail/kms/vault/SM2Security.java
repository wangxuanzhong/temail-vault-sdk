package com.syswin.temail.kms.vault;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.bouncycastle.jce.provider.BouncyCastleProvider.CONFIGURATION;
import static org.bouncycastle.math.ec.ECConstants.ONE;

import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SM2Security implements Security {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private static final String EC = "EC";

  private static final BigInteger GX = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
  private static final BigInteger GY = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
  private static final BigInteger N = new BigInteger("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123", 16);
  private static final BigInteger P = new BigInteger("fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff", 16);
  private static final BigInteger A = new BigInteger("fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc", 16);
  private static final BigInteger B = new BigInteger("28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93", 16);
  private final ECKeyPairGenerator keyPairGenerator;
  private final ECDomainParameters domainParams;
  private final ECParameterSpec ecParamSpec;

  public SM2Security() {
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    ECCurve curve = new ECCurve.Fp(P, A, B, N, ONE);
    ECPoint g = curve.createPoint(GX, GY);

    domainParams = new ECDomainParameters(curve, g, N);
    keyPairGenerator = new ECKeyPairGenerator();
    ecParamSpec = new ECParameterSpec(curve, g, N);
  }

  @Override
  public KeyPair getKeyPair() {
    ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());

    keyPairGenerator.init(keyGenParams);

    final AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
    final BCECPublicKey publicKey = new BCECPublicKey(EC, ((ECPublicKeyParameters) keyPair.getPublic()), ecParamSpec, CONFIGURATION);
    final BCECPrivateKey privateKey = new BCECPrivateKey(EC, ((ECPrivateKeyParameters) keyPair.getPrivate()), publicKey, ecParamSpec, CONFIGURATION);
    return new KeyPair(publicKey, privateKey);
  }

  @Override
  public byte[] encrypt(PublicKey publicKey, String plaintext) throws Exception {
    ECPublicKeyParameters publicKeyParameters = publicKeyParams((BCECPublicKey) publicKey);
    SM2Engine sm2Engine = new SM2Engine();
    sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
    return sm2Engine.processBlock(plaintext.getBytes(), 0, plaintext.getBytes().length);
  }

  @Override
  public String decrypt(PrivateKey privateKey, byte[] encryptedBytes) throws Exception {
    SM2Engine sm2Engine = new SM2Engine();
    ECPrivateKeyParameters privateKeyParameters = privateKeyParameters((BCECPrivateKey) privateKey);
    sm2Engine.init(false, privateKeyParameters);
    byte[] plaintext = sm2Engine.processBlock(encryptedBytes, 0, encryptedBytes.length);
    return new String(plaintext, UTF_8);
  }

  @Override
  public byte[] sign(PrivateKey privateKey, byte[] unsigned) throws Exception {
    ECPrivateKeyParameters privateKeyParameters = privateKeyParameters((BCECPrivateKey) privateKey);

    SM2Signer signer = new SM2Signer();

    signer.init(true,
        new ParametersWithRandom(privateKeyParameters,
            new SecureRandom()));

    signer.update(unsigned, 0, unsigned.length);
    return signer.generateSignature();
  }

  @Override
  public boolean verify(PublicKey publicKey, byte[] unsigned, byte[] signed) {
    ECPublicKeyParameters publicKeyParameters = publicKeyParams((BCECPublicKey) publicKey);
    final SM2Signer signer = new SM2Signer();
    signer.init(false, publicKeyParameters);
    signer.update(unsigned, 0, unsigned.length);
    return signer.verifySignature(signed);
  }

  private ECPrivateKeyParameters privateKeyParameters(BCECPrivateKey privateKey) {
    ECParameterSpec ecParameterSpec = privateKey.getParameters();
    ECDomainParameters ecDomainParameters = new ECDomainParameters(
        ecParameterSpec.getCurve(),
        ecParameterSpec.getG(),
        ecParameterSpec.getN());

    return new ECPrivateKeyParameters(privateKey.getD(), ecDomainParameters);
  }

  private ECPublicKeyParameters publicKeyParams(BCECPublicKey publicKey) {
    ECParameterSpec parameters = publicKey.getParameters();
    ECDomainParameters ecDomainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN());
    return new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);
  }
}
