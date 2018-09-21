package com.syswin.temail.kms.sdk;

import static com.syswin.temail.kms.sdk.utils.CoderUtils.decoder;
import static com.syswin.temail.kms.sdk.utils.CoderUtils.encoder;

import com.syswin.temail.kms.sdk.dto.AsymmetricDto;
import com.syswin.temail.kms.vault.KeyPair;
import com.syswin.temail.kms.vault.cache.ICache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;

public class TSBService {

  private static final Logger LOGGER = LoggerFactory.getLogger(TSBService.class);

  private final CipherService cipherService;
  private final ICache iCache;

  public TSBService(CipherService cipherService, ICache iCache) {
    this.cipherService = cipherService;
    this.iCache = iCache;
  }

  /**
   * [[对称]]加密注册，返回秘钥
   */
  @Cacheable(value = "kms", key = "'SYMMETRIC_KEY_' + #p0")
  public String symmetricRegister(String temail) {
    return cipherService.symmetricRegister(temail);
  }

  /**
   * [[对称]]加密算法的秘钥KEY
   */
  @Cacheable(value = "kms", key = "'SYMMETRIC_KEY_' + #p0")
  public String getSymmetricKey(String temail) {
    return cipherService.getSymmetricKey(temail);
  }

  /**
   * [[对称]]加密
   */
  public String symmetricEncrypt(String keyword, String text) {
    return encoder(cipherService.symmetricEncrypt(keyword, text));
  }

  /**
   * [[对称]]解密
   */
  public String symmetricDecrypt(String keyword, String encrypted) {
    return cipherService.symmetricDecrypt(keyword, decoder(encrypted));
  }

//-----------------------------------------------------------------

  /**
   * [非对称]加密注册，返回公钥
   */
  @Cacheable(value = "kms", key = "'ASYMMETRIC_KEY_' + #p0")
  public String asymmetricRegister(String temail) {
    KeyPair keyPair = iCache.get(temail);
    if (keyPair != null) {
      return keyPair.getPublic();
    }
    AsymmetricDto dto = cipherService.asymmetricRegister(temail);
    keyPair = new KeyPair(decoder(dto.getPrivateKey()), decoder(dto.getPublicKey()));
    iCache.put(temail, keyPair);
    return dto.getPublicKey();
  }

  /**
   * cache中缓存temail
   */
  private String getAsymmetricKeypair(String temail) {
    KeyPair keyPair = iCache.get(temail);
    if (keyPair != null) {
      return keyPair.getPublic();
    }
    AsymmetricDto dto = cipherService.getAsymmetricKeypair(temail);
    keyPair = new KeyPair(decoder(dto.getPrivateKey()), decoder(dto.getPublicKey()));
    iCache.put(temail, keyPair);
    return dto.getPublicKey();
  }

  /**
   * TODO [非对称]公钥
   */
  @Cacheable(value = "kms", key = "'ASYMMETRIC_KEY_' + #p0")
  public String getAsymmetricPubKey(String temail) {
    return getAsymmetricKeypair(temail);
  }

  /**
   * TODO [非对称]签名
   */
  public String sign(String temail, String unsignText) {
    getAsymmetricKeypair(temail);
    return cipherService.sign(temail, unsignText);
  }

  /**
   * TODO [非对称]验证
   */
  @Cacheable(value = "kms", key = "'ASYMMETRIC_VERIFY_' + #p0 + '_' + #p1+ '_' + #p2")
  public boolean asymmetricVerify(String temail, String unsigned, String signed) {
    getAsymmetricKeypair(temail);
    return cipherService.asymmetricVerify(temail, unsigned, signed);
  }

  /**
   * TODO [非对称]加密
   */
  public String asymmetricEncrypt(String temail, String text) {
    getAsymmetricKeypair(temail);
    return cipherService.asymmetricEncrypt(temail, text);
  }

  /**
   * TODO [非对称]解密
   */
  public String asymmetricDecrypt(String temail, String encrypted) {
    getAsymmetricKeypair(temail);
    return cipherService.asymmetricDecrypt(temail, encrypted);
  }


}
