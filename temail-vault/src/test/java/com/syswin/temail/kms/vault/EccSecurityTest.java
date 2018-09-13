package com.syswin.temail.kms.vault;

import static com.seanyinx.github.unit.scaffolding.Randomness.uniquify;
import static org.assertj.core.api.Assertions.assertThat;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Base64;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class EccSecurityTest {

  private static PublicKey publicKey;
  private static PrivateKey privateKey;
  private final byte[] unsigned = uniquify("xyz").getBytes();
  private EccSecurity security;

  @Before
  public void setUp() throws Exception {
    security = new EccSecurity();

    KeyPair keyPair = security.getKeyPair();

    publicKey =  keyPair.getPublic();
    privateKey =  keyPair.getPrivate();
  }

  @Test
  public void shouldVerifySignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    final byte[] signed = security.sign(privateKey, unsigned);

    boolean verified = security.verify(
        publicKey.getEncoded(),
        unsigned,
        signed);

    assertThat(verified).isTrue();
  }

  @Ignore
  @Test
  public void shouldVerifySignatureByClient() {
    final byte[] signed = Base64.getDecoder().decode("TUlHR0FrRUJiNWUydkN3RTBVaDlEQjlnMXFCR0I3VFVVcy9XYmJRTHpVVERRS08ralpCU3RCbDdxd3oyelFya2NkanJkbXNwQ1hVT0dMeEIxblowUDVBNUFjanlqZ0pCU2RIUFE0NGkwL1lQN0RRWXZEMXducGh6U1NjNW9VbTZjNk5nczRDRTVXVnk2dUhoYk51dUwyRXFHY0d3TFo2dkE4WU9vUTJkeEY3MVhSRE05dHIvOVVVPQ==");

    boolean verified = security.verify(
        Base64.getDecoder().decode("TUlHYk1CQUdCeXFHU000OUFnRUdCU3VCQkFBakE0R0dBQVFCZ3c4SU1GZEFzTS9lOEVhSmVDK1B0ODJSMUxUaHFyZDBVbGNsVzdYVllNbkplaHduYnBRKzBPYXVrdHZlRmRIZ3lrMTdHd2d3L0FSRytYN2ZzNWljZXRnQWFNcUltZjlKY3Y3SjRuMEZkRWFoMjYxNUtnNmJ4M3ROcmlZK21NR0hzQnk5SWsvWWQwbmVEdlV0ZlNtbzJPSjRiaG5MdmV2R09UZWRQWmJvbU5WMXRxcz0="),
        "sean@t.email".getBytes(),
        signed);

    assertThat(verified).isTrue();
  }

  @Test
  public void shouldRejectSignatureIfSignedWithDifferentKey()
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {

    byte[] signed = security.sign(security.getKeyPair().getPrivate(), unsigned);

    boolean verified = security.verify(
        publicKey.getEncoded(),
        unsigned,
        signed);

    assertThat(verified).isFalse();
  }

  @Test
  public void shouldRejectSignatureIfNotSigned() {
    boolean verified = security.verify(
        publicKey.getEncoded(),
        unsigned,
        unsigned);

    assertThat(verified).isFalse();
  }
}
