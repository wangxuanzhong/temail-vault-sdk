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

    validateResponse(response);

    KeyPair keyPair = response.getKeyPair();
    cache.put(key, keyPair);
    return keyPair;
  }

  @Override
  public KeyPair retrieve(String tenantId, String key) {
    KeyPair keyPair = cache.get(key);

    if (keyPair == null) {
      Response response = restClient.post(PATH_RETRIEVE, new Request(tenantId, key, algorithm), Response.class);

      validateResponse(response);

      keyPair = response.getKeyPair();
      cache.put(key, keyPair);
    }
    return keyPair;
  }

  @Override
  public void remove(String tenantId, String key) {
    // TODO: 2018/9/21 not supported on server side yet
  }

  private void validateResponse(Response response) {
    if (response == null) {
      throw new VaultCipherException("Failed to generate key pair, response is null");
    }

    KeyPair keyPair = response.getKeyPair();
    if (keyPair == null) {
      throw new VaultCipherException("Failed to generate key pair, key pair is null");
    }

    String publicKey = keyPair.getPublic();
    if (publicKey == null) {
      throw new VaultCipherException("Failed to generate key pair, public key is null");
    }

    String privateKey = keyPair.getPrivate();
    if (privateKey == null) {
      throw new VaultCipherException("Failed to generate key pair, private key is null");
    }
  }
}
