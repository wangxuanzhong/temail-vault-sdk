package com.syswin.temail.kms.vault.infrastructure;

import com.google.gson.Gson;
import com.syswin.temail.kms.vault.RestClient;
import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.lang.invoke.MethodHandles;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

public class HttpClientRestClient implements RestClient {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private final String baseUrl;
  private final Gson gson = new Gson();
  private final List<HttpMessageConverter<?>> messageConverters = new ArrayList<>();
  private final RestTemplate restTemplate;

  public HttpClientRestClient(String baseUrl) {
    this.baseUrl = baseUrl;
    this.messageConverters.add(new StringHttpMessageConverter());
    restTemplate = new RestTemplate(messageConverters);
  }

  @Override
  public <REQUEST, RESPONSE> RESPONSE post(String path, REQUEST request,
      Class<RESPONSE> classType) {
    String url = baseUrl + path;
    try {
      LOG.debug("Sending request to remote url {}", url);
//      HttpResponse response = Request.Post(url)
//          .useExpectContinue()
//          .version(HTTP_1_1)
//          .bodyString(gson.toJson(request), APPLICATION_JSON)
//          .execute()
//          .returnResponse();
//
//      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//      response.getEntity().writeTo(outputStream);
//      String json = outputStream.toString();

      HttpHeaders headers = new HttpHeaders();
      MediaType type = MediaType.parseMediaType("application/json; charset=UTF-8");
      headers.setContentType(type);
      headers.add("Accept", MediaType.APPLICATION_JSON.toString());
      HttpEntity formEntity = new HttpEntity(gson.toJson(request), headers);
      ResponseEntity<String> response = restTemplate
          .postForEntity(url, formEntity, String.class);
      int statusCode = response.getStatusCode().value();
//      int statusCode = response.getStatusLine().getStatusCode();
      String json = response.getBody();
      if (statusCode != 200) {
        LOG.error("Unexpected response from remote url {}: {}", url, json);
        throw new VaultCipherException(
            errorMessage(url) + ", status code = " + statusCode + ", response = " + json);
      }
      return gson.fromJson(json, classType);
    } catch (Exception e) {
      LOG.error("Unexpected response from remote url {}", url, e);
      throw new VaultCipherException(errorMessage(url), e);
    }
  }

  private String errorMessage(String url) {
    return "Failed to fetch content from remote url: " + url;
  }
}
