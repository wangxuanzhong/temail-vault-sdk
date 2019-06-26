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

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;

public interface KeyAwareCipher {

  /**
   * 根据用户ID获取对应密钥进行加密
   * @param userId 账户ID e.g. temail地址
   * @param plaintext 待加密的明文
   * @return 明文加密后对应的密文Base64编码
   * @throws VaultCipherException 因密钥不正确或用户未注册时抛出异常
   */
  String encrypt(String userId, String plaintext);

  /**
   * 根据用户ID获取对应密钥进行解密
   * @param userId 账户ID e.g. temail地址
   * @param encryptedBytes 待解密的密文Base64编码
   * @return 解密后的明文
   * @throws VaultCipherException 因密钥不正确或用户未注册时抛出异常
   */
  String decrypt(String userId, String encryptedBytes);

  /**
   * 根据用户ID获取对应密钥进行签名
   * @param userId 账户ID e.g. temail地址
   * @param plaintext 用于签名的明文
   * @return 明文对应的签名Base64编码
   * @throws VaultCipherException 因密钥不正确或用户未注册时抛出异常
   */
  String sign(String userId, String plaintext);

  /**
   * 根据用户ID获取对应密钥进行验签
   * @param userId 账户ID e.g. temail地址
   * @param plaintext 用于签名的明文
   * @param signed 待验签的签名Base64编码
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
