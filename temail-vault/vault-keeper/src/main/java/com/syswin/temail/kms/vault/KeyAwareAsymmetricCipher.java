package com.syswin.temail.kms.vault;

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import java.util.Optional;

public interface KeyAwareAsymmetricCipher extends KeyAwareCipher {

  /**
   * 账户注册，使用其他非对称接口前须先注册
   * @param userId 账户ID e.g. temail地址
   * @return 该账户对应的公钥
   * @throws VaultCipherException 注册账户时或生成密钥失败抛出
   */
  byte[] register(String userId);

  /**
   * 根据账户ID获取对应公钥
   * @param userId 账户ID e.g. temail地址
   * @return 该账户对应的公钥，若该账户未注册，则返回 {@link Optional#empty()}
   */
  Optional<byte[]> publicKey(String userId);
}
