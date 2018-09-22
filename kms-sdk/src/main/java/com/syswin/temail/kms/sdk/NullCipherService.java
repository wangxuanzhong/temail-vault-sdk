package com.syswin.temail.kms.sdk;

import com.syswin.temail.kms.sdk.dto.AsymmetricDto;
import com.syswin.temail.kms.vault.KeyAwareVault;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.web.client.RestTemplate;

class NullCipherService extends CipherService {

  public NullCipherService(KmsProperties kmsProperties, RestTemplate restTemplate,
      KeyAwareVault vaultKeeper) {
    super(kmsProperties, restTemplate, vaultKeeper);
  }

  /**
   * [[对称]]加密注册，返回秘钥
   */
  public String symmetricRegister(String temail) {
    return temail;
  }

  /**
   * [[对称]]加密算法的秘钥KEY
   */
  public String getSymmetricKey(String temail) {
    return temail;
  }

  /**
   * [[对称]]加密
   */
  public byte[] symmetricEncrypt(String keyword, String text) {
    return keyword.getBytes();
  }

  /**
   * [[对称]]解密
   */
  public String symmetricDecrypt(String keyword, byte[] encrypted) {
    return keyword;
  }

  /**
   * [非对称]签名
   */
  public String sign(String temail, String unsignText) {
    return temail;
  }

  /**
   * [非对称]验证
   */
  public boolean asymmetricVerify(String temail, String unsigned, String signed) {
    return true;
  }

  /**
   * [非对称]加密
   */
  public String asymmetricEncrypt(String temail, String text) {
    return temail;
  }

  /**
   * [非对称]解密
   */
  public String asymmetricDecrypt(String temail, String encrypted) {
    return encrypted;
  }

  @Cacheable(value = "kms", key = "'ASYMMETRIC_KEY_PAIR' + #p0")
  public AsymmetricDto asymmetricRegister(String temail) {
    AsymmetricDto dto = new AsymmetricDto();
    dto.setText(temail);
    dto.setPublicKey(temail);
    dto.setPrivateKey(temail);
    return dto;
  }

  @Cacheable(value = "kms", key = "'ASYMMETRIC_KEY_PAIR' + #p0")
  public AsymmetricDto getAsymmetricKeypair(String temail) {
    AsymmetricDto dto = new AsymmetricDto();
    dto.setText(temail);
    dto.setPublicKey(temail);
    dto.setPrivateKey(temail);
    return dto;
  }

}
