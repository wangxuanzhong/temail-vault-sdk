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

import com.syswin.temail.kms.vault.cache.ICache;
import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.lang.invoke.MethodHandles;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class RemoteKeyRegistry implements KeyRegistry {
  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

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
    LOG.debug("Registering user {} at path {}", key, PATH_REGISTRATION);
    Response response = restClient.post(PATH_REGISTRATION, new Request(tenantId, key, algorithm), Response.class);

    validateResponse(response);

    KeyPair keyPair = response.getKeyPair();
    cache.put(key, keyPair);
    LOG.debug("Registered user {} at path {} with public key [{}]", key, PATH_REGISTRATION, keyPair.getPublic());
    return keyPair;
  }

  @Override
  public KeyPair retrieve(String tenantId, String key) {
    KeyPair keyPair = cache.get(key);

    if (keyPair == null) {
      LOG.debug("No such user {} found locally and retrieving from path {}", key, PATH_RETRIEVE);
      Response response = restClient.post(PATH_RETRIEVE, new Request(tenantId, key, algorithm), Response.class);

      validateResponse(response);

      keyPair = response.getKeyPair();
      cache.put(key, keyPair);
      LOG.debug("Retrieved user {} from path {} with public key [{}]", key, PATH_REGISTRATION, keyPair.getPublic());
    } else {
      LOG.debug("Retrieved user {} locally with public key [{}]", key, keyPair.getPublic());
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
