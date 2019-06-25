package com.syswin.temail.kms.vault.aes;

public interface SymmetricCipher {

  /**
   * 根据指定文字生成Base64编码的keyword
   */
  String getKey(String text);

  /**
   * 加密方法
   * @param key Base64编码的密钥
   * @param plaintext 要加密的字符串
   * @return Base64编码的密文
   */
  String encrypt(String key, String plaintext);

  /**
   * 解密方法
   * @param key Base64编码的密钥
   * @param encrypted 要解密的Base64编码的密文
   * @return 解密后的明文
   */
  String decrypt(String key, String encrypted);
}
