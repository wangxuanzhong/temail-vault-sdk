package com.syswin.temail.kms.vault;


public interface AsymmetricCipher extends PublicKeyCipher {

  KeyPair getKeyPair();

  String decrypt(String privateKey, String encrypted);

  String sign(String privateKey, String plaintext);

}
