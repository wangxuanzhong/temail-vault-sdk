/*
 * MIT License
 *
 * Copyright (c) 2019 Syswin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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

  @SuppressWarnings("unchecked")
  @Test
  public void reuseConnections() throws ExecutionException, InterruptedException {
    int threads = 5;
    ExecutorService executorService = Executors.newFixedThreadPool(threads);

    CyclicBarrier barrier = new CyclicBarrier(threads);
    CompletableFuture<Response>[] futures = new CompletableFuture[threads];
    for (int i = 0; i < threads; i++) {
      futures[i] = CompletableFuture.supplyAsync(() -> {
        try {
          barrier.await();
          return restClient.post(path, new Request(tenantId, "hello@t.email", ECDSA), Response.class);
        } catch (InterruptedException | BrokenBarrierException e) {
          throw new IllegalStateException(e);
        }
      }, executorService);
    }

    CompletableFuture.allOf(futures).join();
    for (int i = 0; i < threads; i++) {
      Response response = futures[i].get();

      assertThat(response.getCode()).isEqualTo(200);
      KeyPair keyPair = response.getKeyPair();

      assertThat(keyPair.getPublic()).isEqualTo("abc");
      assertThat(keyPair.getPrivate()).isEqualTo("xyz");
    }

    executorService.shutdownNow();
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
