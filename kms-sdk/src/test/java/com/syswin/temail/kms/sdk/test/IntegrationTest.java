package com.syswin.temail.kms.sdk.test;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.syswin.temail.kms.vault.CipherAlgorithm.ECDSA;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.apache.http.HttpStatus.SC_OK;
import static org.apache.http.entity.ContentType.APPLICATION_JSON;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.gson.Gson;
import com.syswin.temail.kms.vault.KeyAwareVault;
import com.syswin.temail.kms.vault.Response;
import com.syswin.temail.kms.vault.VaultKeeper;
import java.util.Optional;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = TestApp.class)
public class IntegrationTest {
  @ClassRule
  public static final WireMockRule wireMockRule = new WireMockRule(8094);
  private static final Gson gson = new Gson();

  private static final String eccTemail = "ecctemail@temail.com";

  @Autowired
  private KeyAwareVault vault;

  @BeforeClass
  public static void setUp() {
    stubFor(post(urlEqualTo("/asymmetric/register"))
        .withRequestBody(equalToJson("{\n" +
            "  \"token\": \"syswin\",\n" +
            "  \"text\": \"" + eccTemail + "\",\n" +
            "  \"algorithm\": \"ECDSA\"\n" +
            "}"))
        .willReturn(
            aResponse()
                .withHeader(CONTENT_TYPE, APPLICATION_JSON.getMimeType())
                .withStatus(SC_OK)
                .withBody(gson.toJson(new Response(
                    SC_OK,
                    null,
                    VaultKeeper.keyAwareVault("localhost:8094", "syswin")
                        .plainAsymmetricCipher(ECDSA)
                        .getKeyPair())))));
  }

  @Test
  public void testAll() {
    //temail aes注册
    String temail = "milk" + (System.currentTimeMillis()) + "@temail.com";
    String symmetricKey = vault.symmetricCipher().getKey(temail);

    String text = "milk@t.email中国人";
    //加密
    String encryptedStr = vault.symmetricCipher().encrypt(symmetricKey, text);
    System.out.println("encryptedStr : " + encryptedStr);
    //解密
    String decryptedStr = vault.symmetricCipher().decrypt(symmetricKey, encryptedStr);
    System.out.println("decryptedStr : " + decryptedStr);
    Assert.assertEquals(text, decryptedStr);
    System.out.println("-------------------------------");

    //sdk ecc注册
    String unsign = "this is a text";
    String signature = vault.asymmetricCipher(ECDSA).register(eccTemail);
    System.out.println("asymmetricRegister : " + signature);
    //获取公私钥对
    Optional<String> asymmetricKey = vault.asymmetricCipher(ECDSA).publicKey(eccTemail);
    System.out.println("asymmetricKey : " + asymmetricKey);
    Assert.assertEquals(signature, asymmetricKey.get());

    String txt = vault.asymmetricCipher(ECDSA).encrypt(eccTemail, unsign);
    String a = vault.asymmetricCipher(ECDSA).decrypt(eccTemail, txt);
    Assert.assertEquals(a, unsign);

    //签名
    String sign = vault.asymmetricCipher(ECDSA).sign(eccTemail, unsign);
    System.out.println("signatureStr : " + sign);
    //验证
    boolean verifyResult1 = vault.asymmetricCipher(ECDSA).verify(eccTemail, unsign, sign);
    System.out.println("asymmetricVerifyResult : " + verifyResult1);
    boolean verifyResult2 = vault.asymmetricCipher(ECDSA).verify(eccTemail, unsign, sign);
    System.out.println("asymmetricVerifyResult : " + verifyResult2);
    Assert.assertEquals(verifyResult1, verifyResult2);
  }
}
