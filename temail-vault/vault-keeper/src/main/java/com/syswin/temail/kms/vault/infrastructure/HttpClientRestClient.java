package com.syswin.temail.kms.vault.infrastructure;

import static org.apache.http.HttpVersion.HTTP_1_1;
import static org.apache.http.entity.ContentType.APPLICATION_JSON;

import com.google.gson.Gson;
import com.syswin.temail.kms.vault.RestClient;
import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
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
      String json = Request.Post(url)
          .useExpectContinue()
          .version(HTTP_1_1)
          .bodyString(gson.toJson(request), APPLICATION_JSON)
          .execute()
          .returnContent()
          .asString();

      return gson.fromJson(json, classType);
    } catch (Exception e) {
      throw new VaultCipherException("Failed to fetch content from remote url: " + url, e);
    }
  }
}
