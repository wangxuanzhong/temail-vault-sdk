package com.syswin.temail.kms.vault;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static com.syswin.temail.kms.vault.CipherAlgorithm.ECDSA;
import static org.assertj.core.api.Assertions.assertThat;
import static wiremock.org.apache.http.HttpHeaders.CONTENT_TYPE;
import static wiremock.org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static wiremock.org.apache.http.HttpStatus.SC_OK;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.github.tomakehurst.wiremock.matching.EqualToJsonPattern;
import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import com.syswin.temail.kms.vault.infrastructure.HttpClientRestClient;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import wiremock.org.apache.http.entity.ContentType;

public class RestClientTest {

  @ClassRule
  public static final WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort());
  private static final String path = "/asymmetric/register";

  private final String tenantId = "syswin";
  private HttpClientRestClient restClient;

  @BeforeClass
  public static void beforeClass() {
    stubFor(post(urlEqualTo(path))
        .withRequestBody(new EqualToJsonPattern("{\n"
            + "  \"token\": \"syswin\",\n"
            + "  \"text\": \"hello@t.email\",\n"
            + "  \"algorithm\": \"ECDSA\"\n"
            + "}", true, false))
        .willReturn(
            aResponse()
                .withHeader(CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                .withStatus(SC_OK)
                .withBody("{\n"
                    + "  \"code\": 200,\n"
                    + "  \"data\": {\n"
                    + "    \"token\": \"syswin\",\n"
                    + "    \"text\": \"hello@t.email\",\n"
                    + "    \"algorithm\": \"ECDSA\",\n"
                    + "    \"publicKey\": \"abc\",\n"
                    + "    \"privateKey\": \"xyz\"\n"
                    + "  }\n"
                    + "}")));

    stubFor(post(urlEqualTo(path))
        .withRequestBody(new EqualToJsonPattern("{\n"
            + "  \"token\": \"syswin\",\n"
            + "  \"text\": \"fake@t.email\",\n"
            + "  \"algorithm\": \"ECDSA\"\n"
            + "}", true, false))
        .willReturn(
            aResponse()
                .withHeader(CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType())
                .withStatus(SC_INTERNAL_SERVER_ERROR)
                .withBody("{\n"
                    + "  \"code\": 500,\n"
                    + "  \"data\": {\n"
                    + "    \"token\": \"syswin\",\n"
                    + "    \"text\": \"hello@t.email\",\n"
                    + "    \"algorithm\": \"ECDSA\",\n"
                    + "    \"publicKey\": \"abc\",\n"
                    + "    \"privateKey\": \"xyz\"\n"
                    + "  }\n"
                    + "}")));
  }

  @Before
  public void setUp() {
    restClient = new HttpClientRestClient("http://localhost:" + wireMockRule.port());
  }

  @Test
  public void generateKeyFromRemote() {
    Response response = restClient.post(path, new Request(tenantId, "hello@t.email", ECDSA), Response.class);
    assertThat(response.getCode()).isEqualTo(200);

    KeyPair keyPair = response.getKeyPair();

    assertThat(keyPair.getPublic()).isEqualTo("abc");
    assertThat(keyPair.getPrivate()).isEqualTo("xyz");
  }

  @Test(expected = VaultCipherException.class)
  public void blowsUpIfResponseIsNot200() {
    restClient.post(path, new Request(tenantId, "fake@t.email", ECDSA), Response.class);
  }

  @Test(expected = VaultCipherException.class)
  public void blowsUpIfRemoteUnreachable() {
    new HttpClientRestClient("http://localhost:90").post(path, new Request(tenantId, "fake@t.email", ECDSA), Response.class);
  }
}
