package com.syswin.temail.kms.vault;

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;

public interface PublicKeyCipher {

  /**
   * 使用提供的密钥进行加密
   * @param publicKey 公钥Base64编码
   * @param plaintext 待加密的明文
   * @return 明文加密后对应的密文Base64编码
   * @throws VaultCipherException 因密钥不正确时抛出异常
   */
  String encrypt(String publicKey, String plaintext);

  /**
   * 使用提供的密钥进行验签
   * @param publicKey 公钥Base64编码
   * @param plaintext 用于签名的明文
   * @param signed 待验签的签名Base64编码
   * @return 签名是否与明文匹配
   */
  boolean verify(String publicKey, String plaintext, String signature);

  CipherAlgorithm algorithm();
}
