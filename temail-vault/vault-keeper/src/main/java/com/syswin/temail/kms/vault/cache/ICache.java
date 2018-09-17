package com.syswin.temail.kms.vault.cache;

import com.syswin.temail.kms.vault.KeyPair;

public interface ICache {

  void put(String key, KeyPair value);

  KeyPair get(String key);

  void remove(String key);

}
