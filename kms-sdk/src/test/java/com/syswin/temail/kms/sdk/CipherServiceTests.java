package com.syswin.temail.kms.sdk;

import static com.syswin.temail.kms.sdk.CipherService.AES;
import static com.syswin.temail.kms.sdk.CipherService.ALGORITHM;
import static com.syswin.temail.kms.sdk.CipherService.TEXT;

import com.syswin.temail.kms.vault.VaultKeeper;
import com.syswin.temail.kms.vault.aes.AESCipher;
import com.syswin.temail.kms.vault.aes.SymmetricCipher;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.web.client.RestTemplate;

public class CipherServiceTests {

  public static final String URL_SYMMETRIC_REGISTER = "http://127.0.0.1:8094/symmetric/register";
  public static final String URL_SYMMETRIC_KEY = "http://127.0.0.1:8094/symmetric/key";
  public static final String keyword = "keyword@temail.com";
  private KmsProperties kmsProperties = Mockito.mock(KmsProperties.class);
  private RestTemplate restTemplate = Mockito.mock(RestTemplate.class);
  private VaultKeeper vaultKeeper = Mockito.mock(VaultKeeper.class);
  private CipherService cipherService = new CipherService(kmsProperties, restTemplate, vaultKeeper);
  private SymmetricCipher aesCipher;
  private String temail;
  private String encrypted;

  @Before
  public void before() {
    aesCipher = new AESCipher(keyword);
  }

  /**
   * [[对称]]加密注册，返回秘钥
   */
  @Test
  public void symmetricRegister() {
    Map map = new HashMap();
    map.put(TEXT, "temail");
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
    temail = "temail";
    encrypted = "this is test";
    byte[] s = cipherService.symmetricEncrypt(temail, encrypted);
    String s1 = cipherService.symmetricDecrypt(temail, s);
    Assert.assertEquals(s1, encrypted);
  }

}
