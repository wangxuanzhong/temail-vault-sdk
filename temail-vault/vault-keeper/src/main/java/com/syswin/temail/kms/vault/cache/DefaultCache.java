package com.syswin.temail.kms.vault.cache;

import com.syswin.temail.kms.vault.KeyPair;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DefaultCache implements ICache {

  private final Map<String, KeyPair> userKeys = new ConcurrentHashMap<>();

  @Override
  public void put(String key, KeyPair value) {
    userKeys.put(key, value);
  }

  @Override
  public KeyPair get(String key) {
    return userKeys.get(key);
  }

  @Override
  public void remove(String key) {
    userKeys.remove(key);
  }
}
