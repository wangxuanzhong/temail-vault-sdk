package com.syswin.temail.kms.vault;

public interface RestClient {
  <REQUEST, RESPONSE> RESPONSE post(String url, REQUEST request, Class<RESPONSE> classType);
}
