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
   * @param signature 待验签的签名Base64编码
   * @return 签名是否与明文匹配
   */
  boolean verify(String publicKey, String plaintext, String signature);

  CipherAlgorithm algorithm();
}
