package com.syswin.temail.kms.sdk;

import static com.syswin.temail.kms.sdk.CipherService.AES;
import static com.syswin.temail.kms.sdk.CipherService.ALGORITHM;
import static com.syswin.temail.kms.sdk.CipherService.ECDSA;
import static com.syswin.temail.kms.sdk.CipherService.TEXT;

import com.syswin.temail.kms.sdk.dto.AsymmetricDto;
import com.syswin.temail.kms.vault.VaultKeeper;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.web.client.RestTemplate;

public class CipherServiceTests {

  private static final String URL_SYMMETRIC_REGISTER = "http://127.0.0.1:8094/symmetric/register";
  private static final String URL_SYMMETRIC_KEY = "http://127.0.0.1:8094/symmetric/key";
  private static final String URL_ASYMMETRIC_REGISTER = "http://127.0.0.1:8094/asymmetric/register";
  private static final String URL_ASYMMETRIC_KEY = "http://127.0.0.1:8094/asymmetric/key";

  private KmsProperties kmsProperties = Mockito.mock(KmsProperties.class);
  private RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
  private VaultKeeper vaultKeeper = Mockito.mock(VaultKeeper.class);
  private CipherService cipherService = new CipherService(kmsProperties, restTemplate, vaultKeeper);
  private String temail;
  private String encrypted;

  @Before
  public void before() {
    temail = "temail";
    encrypted = "this is test";
  }

  /**
   * [[对称]]加密注册，返回秘钥
   */
  @Test
  public void symmetricRegister() {
    Map map = new HashMap();
    map.put(TEXT, temail);
    map.put(ALGORITHM, AES);
    Mockito.when(kmsProperties.getUrlSymmetricRegister()).thenReturn(URL_SYMMETRIC_REGISTER);
    Mockito.when(cipherService.post(URL_SYMMETRIC_REGISTER, map)).thenReturn("{\n"
        + "\t\"code\": 200,\n"
        + "\t\"message\": \"success\",\n"
        + "\t\"data\": {\n"
        + "\t\t\"text\": \"temail\",\n"
        + "\t\t\"secretKey\": \"abc-key\",\n"
        + "\t\t\"algorithm\": \"AES\"\n"
        + "\t}\n"
        + "}");
    String result = cipherService.symmetricRegister("temail");
    Assert.assertEquals(result, "abc-key");
  }

  @Test
  public void getSymmetricKey() {
    Map map = new HashMap();
    map.put(TEXT, "temail");
    Mockito.when(kmsProperties.getUrlSymmetricKey()).thenReturn(URL_SYMMETRIC_KEY);
    Mockito.when(cipherService.post(URL_SYMMETRIC_KEY, map)).thenReturn("{\n"
        + "\t\"code\": 200,\n"
        + "\t\"message\": \"success\",\n"
        + "\t\"data\": {\n"
        + "\t\t\"text\": \"temail\",\n"
        + "\t\t\"secretKey\": \"abc-key\",\n"
        + "\t\t\"algorithm\": \"AES\"\n"
        + "\t}\n"
        + "}");
    String result = cipherService.getSymmetricKey("temail");
    Assert.assertEquals(result, "abc-key");
  }

  @Test
  public void symmetricEncrypt() {

    byte[] s = cipherService.symmetricEncrypt(temail, encrypted);
    String s1 = cipherService.symmetricDecrypt(temail, s);
    Assert.assertEquals(s1, encrypted);
  }

  @Test
  public void asymmetricRegister() {
    Map map = new HashMap();
    map.put(TEXT, temail);
    map.put(ALGORITHM, ECDSA);
    Mockito.when(kmsProperties.getUrlAsymmetricRegister()).thenReturn(URL_ASYMMETRIC_REGISTER);
    Mockito.when(cipherService.post(URL_ASYMMETRIC_REGISTER, map)).thenReturn("{\n"
        + "\t\"code\": 200,\n"
        + "\t\"message\": \"success\",\n"
        + "\t\"data\": {\n"
        + "\t\t\"text\": \"temail\",\n"
        + "\t\t\"publicKey\": \"publicKey\",\n"
        + "\t\t\"privateKey\": \"privateKey\",\n"
        + "\t\t\"algorithm\": \"ECDSA\"\n"
        + "\t}\n"
        + "}");
    AsymmetricDto dto = cipherService.asymmetricRegister(temail);
    Assert.assertNotNull(dto);
    Assert.assertEquals(dto.getPublicKey(), "publicKey");
    Assert.assertEquals(dto.getPrivateKey(), "privateKey");
    Assert.assertEquals(dto.getAlgorithm(), ECDSA);
  }

  @Test
  public void asymmetricKey() {
    Map map = new HashMap();
    map.put(TEXT, temail);
    Mockito.when(kmsProperties.getUrlAsymmetricKey()).thenReturn(URL_ASYMMETRIC_KEY);
    Mockito.when(cipherService.post(URL_ASYMMETRIC_KEY, map)).thenReturn("{\n"
        + "\t\"code\": 200,\n"
        + "\t\"message\": \"success\",\n"
        + "\t\"data\": {\n"
        + "\t\t\"text\": \"temail\",\n"
        + "\t\t\"publicKey\": \"publicKey\",\n"
        + "\t\t\"privateKey\": \"privateKey\",\n"
        + "\t\t\"algorithm\": \"ECDSA\"\n"
        + "\t}\n"
        + "}");
    AsymmetricDto dto = cipherService.getAsymmetricKeypair(temail);
    Assert.assertNotNull(dto);
    Assert.assertEquals(dto.getPublicKey(), "publicKey");
    Assert.assertEquals(dto.getPrivateKey(), "privateKey");
    Assert.assertEquals(dto.getAlgorithm(), ECDSA);
  }

}
