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
import java.util.Optional;

public interface KeyAwareAsymmetricCipher extends KeyAwareCipher {

  /**
   * 账户注册，使用其他非对称接口前须先注册
   * @param userId 账户ID e.g. temail地址
   * @return 该账户对应的公钥Base64编码
   * @throws VaultCipherException 注册账户时或生成密钥失败抛出
   */
  String register(String userId);

  /**
   * 根据账户ID获取对应公钥
   * @param userId 账户ID e.g. temail地址
   * @return 该账户对应的公钥Base64编码，若该账户未注册，则返回 {@link Optional#empty()}
   */
  Optional<String> publicKey(String userId);
}
