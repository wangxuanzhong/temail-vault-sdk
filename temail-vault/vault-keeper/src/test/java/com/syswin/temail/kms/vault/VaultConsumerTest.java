package com.syswin.temail.kms.vault;

import static com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.ANY;
import static com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.NONE;
import static com.fasterxml.jackson.annotation.PropertyAccessor.FIELD;
import static com.fasterxml.jackson.annotation.PropertyAccessor.GETTER;
import static com.syswin.temail.kms.vault.CipherAlgorithm.ECDSA;
import static com.syswin.temail.kms.vault.RemoteKeyRegistry.PATH_REGISTRATION;
import static com.syswin.temail.kms.vault.RemoteKeyRegistry.PATH_RETRIEVE;
import static java.util.Collections.singletonMap;
import static org.apache.http.entity.ContentType.APPLICATION_JSON;
import static org.assertj.core.api.Assertions.assertThat;
import static wiremock.org.apache.http.HttpHeaders.CONTENT_TYPE;

import au.com.dius.pact.consumer.ConsumerPactTestMk2;
import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.model.RequestResponsePact;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.syswin.temail.kms.vault.infrastructure.HttpClientRestClient;
import java.util.HashMap;
import java.util.Map;
import org.junit.Before;

public class VaultConsumerTest extends ConsumerPactTestMk2 {

  private final ObjectMapper objectMapper = new ObjectMapper();
  private final String publicKey = "world";
  private final String privateKey = "hello";
  private final KeyPair keyPair = new KeyPair(privateKey, publicKey);

  private final String tenantId = "syswin";
  private final String userId = "sean@t.email";
  private final Request request = new Request(tenantId, userId, ECDSA);

  @Before
  public void setUp() {
    objectMapper.setSerializationInclusion(Include.NON_NULL)
        .setVisibility(FIELD, ANY)
        .setVisibility(GETTER, NONE)
    ;
  }

  // TODO: 2018/9/22 exceptional cases to be added
  @Override
  public RequestResponsePact createPact(PactDslWithProvider pactDslWithProvider) {
    Map<String, String> headers = new HashMap<>();
    headers.put(CONTENT_TYPE, APPLICATION_JSON.getMimeType());

    try {
      return pactDslWithProvider
          .given("Register - kms is ready")
            .uponReceiving("request to register from Sean")
            .method("POST")
            .body(objectMapper.writeValueAsString(request))
            .headers(headers)
            .path(PATH_REGISTRATION)
            .willRespondWith()
            .status(200)
            .headers(singletonMap(CONTENT_TYPE, APPLICATION_JSON.getMimeType()))
            .body(objectMapper.writeValueAsString(new Response(200, "success", keyPair)))
          .given("Retrieve - kms is ready")
            .uponReceiving("request to retrieve keys of Sean")
            .method("POST")
            .body(objectMapper.writeValueAsString(request))
            .headers(headers)
            .path(PATH_RETRIEVE)
            .willRespondWith()
            .status(200)
            .headers(singletonMap(CONTENT_TYPE, APPLICATION_JSON.getMimeType()))
            .body(objectMapper.writeValueAsString(new Response(200, "success", keyPair)))
          .toPact();
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public void runTest(MockServer mockServer) {
    RestClient client = new HttpClientRestClient(mockServer.getUrl());
    Response response = client.post(PATH_REGISTRATION, request, Response.class);

    assertThat(response.getCode()).isEqualTo(200);
    assertThat(response.getKeyPair()).isEqualToComparingFieldByField(keyPair);

    response = client.post(PATH_RETRIEVE, request, Response.class);

    assertThat(response.getCode()).isEqualTo(200);
    assertThat(response.getKeyPair()).isEqualToComparingFieldByField(keyPair);
  }

  @Override
  protected String providerName() {
    return "temail-kms-server";
  }

  @Override
  protected String consumerName() {
    return "temail-kms-sdk";
  }
}
