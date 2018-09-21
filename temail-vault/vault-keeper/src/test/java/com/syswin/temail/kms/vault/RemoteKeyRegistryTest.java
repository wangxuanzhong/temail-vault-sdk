package com.syswin.temail.kms.vault;

import static com.seanyinx.github.unit.scaffolding.AssertUtils.expectFailing;
import static com.seanyinx.github.unit.scaffolding.Randomness.uniquify;
import static com.syswin.temail.kms.vault.CipherAlgorithm.ECDSA;
import static com.syswin.temail.kms.vault.RemoteKeyRegistry.PATH_REGISTRATION;
import static com.syswin.temail.kms.vault.RemoteKeyRegistry.PATH_RETRIEVE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.syswin.temail.kms.vault.cache.ICache;
import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import org.junit.Test;
import org.mockito.Mockito;

public class RemoteKeyRegistryTest {

  private final String tenantId = uniquify("tenantId");
  private final String userId = uniquify("userId");

  private final byte[] publicKey = "abc".getBytes();
  private final byte[] privateKey = "xyz".getBytes();
  private final KeyPair keyPair = new KeyPair(privateKey, publicKey);
  private final Request request = new Request(tenantId, userId, ECDSA);

  private final ICache iCache = Mockito.mock(ICache.class);
  private final RestClient restClient = Mockito.mock(RestClient.class);
  private final RemoteKeyRegistry cache = new RemoteKeyRegistry(iCache, restClient, ECDSA);

  @Test
  public void generateKeyFromRemote() {
    when(restClient.post(PATH_REGISTRATION, request, Response.class))
        .thenReturn(new Response(200, null, keyPair));

    KeyPair keyPair = cache.register(tenantId, userId);

    assertThat(keyPair).isEqualTo(this.keyPair);
    verify(iCache).put(userId, this.keyPair);
  }

  @Test
  public void blowsUpIfResponseCodeIsNot200OnRegister() {
    when(restClient.post(PATH_REGISTRATION, request, Response.class))
        .thenReturn(new Response(500, "oops", null));

    try {
      cache.register(tenantId, userId);
      expectFailing(VaultCipherException.class);
    } catch (VaultCipherException e) {
      assertThat(e).hasMessage("Failed to generate key pair, error message is: oops");
    }

    verify(iCache, never()).put(anyString(), any(KeyPair.class));
  }

  @Test
  public void fetchKeyFromRemoteIfNotCached() {
    when(restClient.post(PATH_RETRIEVE, request, Response.class))
        .thenReturn(new Response(200, null, keyPair));

    KeyPair keyPair = cache.retrieve(tenantId, userId);

    assertThat(keyPair).isEqualTo(this.keyPair);
    verify(iCache).put(userId, keyPair);
  }

  @Test
  public void fetchKeyFromCache() {
    when(iCache.get(userId)).thenReturn(keyPair);

    KeyPair keyPair = cache.retrieve(tenantId, userId);

    assertThat(keyPair).isEqualTo(this.keyPair);

    verify(iCache, never()).put(anyString(), any(KeyPair.class));
    verify(restClient, never()).post(eq(PATH_RETRIEVE), any(Request.class), eq(Response.class));
  }

  @Test
  public void blowsUpIfResponseCodeIsNot200OnRetrieve() {
    when(restClient.post(PATH_RETRIEVE, request, Response.class))
        .thenReturn(new Response(500, "oops", null));

    try {
      cache.retrieve(tenantId, userId);
      expectFailing(VaultCipherException.class);
    } catch (VaultCipherException e) {
      assertThat(e).hasMessage("Failed to generate key pair, error message is: oops");
    }

    verify(iCache, never()).put(anyString(), any(KeyPair.class));
  }
}