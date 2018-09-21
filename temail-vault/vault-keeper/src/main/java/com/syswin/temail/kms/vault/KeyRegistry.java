package com.syswin.temail.kms.vault;

interface KeyRegistry {

  KeyPair register(String key);

  KeyPair retrieve(String key);

  void remove(String key);
}
