package com.syswin.temail.kms.vault;

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;

public interface KeyAwareCipher {

  /**
   * 根据用户ID获取对应密钥进行加密
   * @param userId 账户ID e.g. temail地址
   * @param plaintext 待加密的明文
   * @return 明文加密后对应的密文
   * @throws VaultCipherException 因密钥不正确或用户未注册时抛出异常
   */
  String encrypt(String userId, String plaintext);

  /**
   * 根据用户ID获取对应密钥进行解密
   * @param userId 账户ID e.g. temail地址
   * @param encryptedBytes 待解密的密文
   * @return 解密后的明文
   * @throws VaultCipherException 因密钥不正确或用户未注册时抛出异常
   */
  String decrypt(String userId, String encryptedBytes);

  /**
   * 根据用户ID获取对应密钥进行签名
   * @param userId 账户ID e.g. temail地址
   * @param plaintext 用于签名的明文
   * @return 明文对应的签名
   * @throws VaultCipherException 因密钥不正确或用户未注册时抛出异常
   */
  String sign(String userId, String plaintext);

  /**
   * 根据用户ID获取对应密钥进行验签
   * @param userId 账户ID e.g. temail地址
   * @param plaintext 用于签名的明文
   * @param signed 待验签的签名
   * @return 签名是否与明文匹配
   * @throws VaultCipherException 因密钥不正确或用户未注册时抛出异常
   */
  boolean verify(String userId, String plaintext, String signed);

  /**
   * 删除管理的用户及其密钥
   * @param userId 账户ID e.g. temail地址
   */
  void revoke(String userId);

  /**
   *
   * @return 该实现的底层算法
   */
  CipherAlgorithm algorithm();
}
