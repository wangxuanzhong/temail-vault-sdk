package com.syswin.temail.kms.vault.infrastructure;

import static org.apache.http.HttpVersion.HTTP_1_1;
import static org.apache.http.entity.ContentType.APPLICATION_JSON;

import com.google.gson.Gson;
import com.syswin.temail.kms.vault.RestClient;
import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.io.ByteArrayOutputStream;
import org.apache.http.HttpResponse;
import org.apache.http.client.fluent.Request;

public class HttpClientRestClient implements RestClient {

  private final String baseUrl;
  private final Gson gson = new Gson();

  public HttpClientRestClient(String baseUrl) {
    this.baseUrl = baseUrl;
  }

  @Override
  public <REQUEST, RESPONSE> RESPONSE post(String path, REQUEST request, Class<RESPONSE> classType) {
    String url = baseUrl + path;
    try {
      HttpResponse response = Request.Post(url)
          .useExpectContinue()
          .version(HTTP_1_1)
          .bodyString(gson.toJson(request), APPLICATION_JSON)
          .execute()
          .returnResponse();

      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      response.getEntity().writeTo(outputStream);
      String json = outputStream.toString();

      int statusCode = response.getStatusLine().getStatusCode();
      if (statusCode != 200) {
        throw new VaultCipherException(errorMessage(url) + ", status code = " + statusCode + ", response = " + json);
      }

      return gson.fromJson(json, classType);
    } catch (Exception e) {
      throw new VaultCipherException(errorMessage(url), e);
    }
  }

  private String errorMessage(String url) {
    return "Failed to fetch content from remote url: " + url;
  }
}
