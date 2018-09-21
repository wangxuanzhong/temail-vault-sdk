package com.syswin.temail.kms.vault;

interface KeyRegistry {

  KeyPair register(String tenantId, String key);

  KeyPair retrieve(String tenantId, String key);

  void remove(String tenantId, String key);
}
