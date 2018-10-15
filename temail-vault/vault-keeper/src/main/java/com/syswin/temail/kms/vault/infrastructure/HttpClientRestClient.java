package com.syswin.temail.kms.vault.infrastructure;

import static org.apache.http.entity.ContentType.APPLICATION_JSON;

import com.google.gson.Gson;
import com.syswin.temail.kms.vault.RestClient;
import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.lang.invoke.MethodHandles;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpClientRestClient implements RestClient {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private final String baseUrl;
  private final Gson gson = new Gson();
  private final CloseableHttpClient client;

  public HttpClientRestClient(String baseUrl) {
    this.baseUrl = baseUrl;

    client = HttpClientConfig.getInstance().httpClient(baseUrl);
  }

  @Override
  public <REQUEST, RESPONSE> RESPONSE post(String path, REQUEST request,
      Class<RESPONSE> classType) {
    String url = baseUrl + path;
    try {
      LOG.debug("Sending request to remote url {}", url);
      HttpPost httpPost = new HttpPost(url);

      StringEntity entity = new StringEntity(gson.toJson(request));
      httpPost.setEntity(entity);
      httpPost.setHeader("Content-Type", APPLICATION_JSON.getMimeType());

      CloseableHttpResponse response = client.execute(httpPost);
      String json = EntityUtils.toString(response.getEntity());

      int statusCode = response.getStatusLine().getStatusCode();
      if (statusCode != 200) {
        LOG.error("Unexpected response from remote url {}: {}", url, json);
        throw new VaultCipherException(
            errorMessage(url) + ", status code = " + statusCode + ", response = " + json);
      }
      return gson.fromJson(json, classType);
    } catch (Exception e) {
      LOG.error("Unexpected response from remote url {}", url, e);
      throw new VaultCipherException(errorMessage(url, e), e);
    }
  }

  private String errorMessage(String url) {
    return "Failed to fetch content from remote url: " + url;
  }

  private String errorMessage(String url, Exception e) {
    return "Failed to fetch content from remote url: " + url + "," + e.getMessage();
  }
}
