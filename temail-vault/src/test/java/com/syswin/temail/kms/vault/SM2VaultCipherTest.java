package com.syswin.temail.kms.vault;

import static com.seanyinx.github.unit.scaffolding.Randomness.uniquify;
import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class SM2VaultCipherTest {

  private static PublicKey publicKey;
  private static PrivateKey privateKey;
  private final byte[] unsigned = uniquify("xyz").getBytes();
  private SM2VaultCipher security;

  @Before
  public void setUp() throws Exception {
    security = new SM2VaultCipher();

    KeyPair keyPair = security.getKeyPair();

    publicKey =  keyPair.getPublic();
    privateKey =  keyPair.getPrivate();
    System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
  }

  @Test
  public void shouldVerifySignature() throws Exception {
    final byte[] signed = security.sign(privateKey, unsigned);

    boolean verified = security.verify(
        publicKey,
        unsigned,
        signed);

    assertThat(verified).isTrue();
  }

  @Ignore
  @Test
  public void shouldVerifySignatureByClient() {
//    final byte[] signed = Base64.getDecoder().decode("TUlHSUFrSUIxeTJTZXhkKzVmYXlIVzIySUVRQjZUa1l3UFgwbmI3L1pzVVVmdSs0eUxXVW03NG9EbnpBV3M5ejdNOCtWUldCZlhaODF1RVhTWGUrNE9reStHNm9vMWNDUWdGM0JDZk5tRmhEMUxCd1YzQTFyRkYzdFJVZCt3UitpT0gwbis5NmNOTG5UbFhvUURDL2VhUE5qUGN1VEdpTDgvOXpUZjcxUkF2R21JenVHbEpIUXhDR0pBPT0=");
//
//    boolean verified = security.verify(
//        Base64.getDecoder().decode("TUlHYk1CQUdCeXFHU000OUFnRUdCU3VCQkFBakE0R0dBQVFCOFZVMHk5QmdXbUNReHBSTzdYNXc2MHlsTHlCOGZBOGJtYzk4eTh2R0VQaWcycXBFL2JOTEpGMGxHT09NVXkrSmxPdGcxekFtYU16bWVSWFFrcFJtZERRQU84eUNzb2sxbE4rUTZyV0ttNEpnZ1J1VmZKOE9nenM4WDNleURHTGthQ2lJTk9tQWZtOWdNNDNNL2hETFloaTU5TGtZcGp0Z3VraldrRkVqeWJwUitmRT0="),
//        "sean@t.email".getBytes(),
//        signed);
//
//    assertThat(verified).isTrue();
  }

  @Test
  public void shouldRejectSignatureIfSignedWithDifferentKey() throws Exception {
    byte[] signed = security.sign(security.getKeyPair().getPrivate(), unsigned);

    boolean verified = security.verify(
        publicKey,
        unsigned,
        signed);

    assertThat(verified).isFalse();
  }

  @Test
  public void shouldRejectSignatureIfNotSigned() {
    boolean verified = security.verify(
        publicKey,
        unsigned,
        unsigned);

    assertThat(verified).isFalse();
  }

  @Test
  public void shouldDecryptEncrypted() throws Exception {
    final byte[] encrypted = security.encrypt(publicKey, new String(unsigned));

    final String decrypted = security.decrypt(privateKey, encrypted);
    assertThat(decrypted).isEqualTo(new String(unsigned));
  }

  @Test
  public void shouldDecryptMsgFromClient() throws Exception {
//    final SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(
//        "TUlHYk1CQUdCeXFHU000OUFnRUdCU3VCQkFBakE0R0dBQVFCOFZVMHk5QmdXbUNReHBSTzdYNXc2MHlsTHlCOGZBOGJtYzk4eTh2R0VQaWcycXBFL2JOTEpGMGxHT09NVXkrSmxPdGcxekFtYU16bWVSWFFrcFJtZERRQU84eUNzb2sxbE4rUTZyV0ttNEpnZ1J1VmZKOE9nenM4WDNleURHTGthQ2lJTk9tQWZtOWdNNDNNL2hETFloaTU5TGtZcGp0Z3VraldrRkVqeWJwUitmRT0="),
//        ALG_PARAM);
//
//    final String decrypted = security.decrypt(keySpec, Base64.getDecoder().decode(
//        "AAAAQwAAAEAAAAAQAAAADAMAYK3mrEKWOKRol2QLYVrvbRZ/cpOpRDtQV/VoDYgu9ay2whUZ+sZ1HKRSu4hoqwhvNVqnX/6tr88Bxj3Q+xUQUO8JcrlRD8Xi4lqeWBRly2whuYnwaPXI2WNxGkdV+Lso6i93LXb/DNo0VET55ls/AzGb41mo3DbG9spTTDY7mcDibcp4Zi52yEui/luvurVvgg=="));
//
//    System.out.println(decrypted);
  }
}
