package com.syswin.temail.kms.vault;

import com.syswin.temail.kms.vault.cache.ICache;
import com.syswin.temail.kms.vault.exceptions.VaultCipherException;

class RemoteKeyRegistry implements KeyRegistry {

  static final String PATH_REGISTRATION = "/asymmetric/register";
  static final String PATH_RETRIEVE = "/asymmetric/key";

  private final ICache cache;
  private final RestClient restClient;
  private final CipherAlgorithm algorithm;

  RemoteKeyRegistry(ICache cache, RestClient restClient, CipherAlgorithm algorithm) {
    this.cache = cache;
    this.restClient = restClient;
    this.algorithm = algorithm;
  }

  @Override
  public KeyPair register(String tenantId, String key) {
    Response response = restClient.post(PATH_REGISTRATION, new Request(tenantId, key, algorithm), Response.class);

    if (response.getCode() != 200) {
      throw new VaultCipherException("Failed to generate key pair, error message is: " + response.getMessage());
    }

    KeyPair keyPair = response.getKeyPair();
    cache.put(key, keyPair);
    return keyPair;
  }

  @Override
  public KeyPair retrieve(String tenantId, String key) {
    KeyPair keyPair = cache.get(key);

    if (keyPair == null) {
      Response response = restClient.post(PATH_RETRIEVE, new Request(tenantId, key, algorithm), Response.class);

      if (response.getCode() != 200) {
        throw new VaultCipherException("Failed to generate key pair, error message is: " + response.getMessage());
      }

      keyPair = response.getKeyPair();
      cache.put(key, keyPair);
    }
    return keyPair;
  }

  @Override
  public void remove(String tenantId, String key) {
    // TODO: 2018/9/21 not supported on server side yet
  }
}
