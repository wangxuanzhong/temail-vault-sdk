package com.syswin.temail.kms.sdk;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import com.syswin.temail.kms.sdk.dto.AsymmetricDto;
import com.syswin.temail.kms.sdk.dto.SymmetricDto;
import com.syswin.temail.kms.sdk.exception.KmsException;
import com.syswin.temail.kms.vault.CipherAlgorithm;
import com.syswin.temail.kms.vault.VaultKeeper;
import com.syswin.temail.kms.vault.aes.AESCipher;
import com.syswin.temail.kms.vault.aes.SymmetricCipher;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

class CipherService {

  private static final Logger LOGGER = LoggerFactory.getLogger(CipherService.class);
  private final KmsProperties kmsProperties;
  private final RestTemplate restTemplate;
  private final VaultKeeper vaultKeeper;

  public CipherService(KmsProperties kmsProperties, RestTemplate restTemplate, VaultKeeper vaultKeeper) {
    this.kmsProperties = kmsProperties;
    this.restTemplate = restTemplate;
    this.vaultKeeper = vaultKeeper;
  }

  /**
   * [[对称]]加密注册，返回秘钥
   */
  public String symmetricRegister(String temail) {
    Map map = new HashMap();
    map.put("text", temail);
    String result = post(kmsProperties.getUrlSymmetricRegister(), map);
    SymmetricDto data = new Gson().fromJson(new JsonParser().parse(result).getAsJsonObject().get("data"), SymmetricDto.class);
    return data.getSecretKey();
  }

  /**
   * [[对称]]加密算法的秘钥KEY
   */
  public String getSymmetricKey(String temail) {
    Map map = new HashMap();
    map.put("text", temail);
    String result = post(kmsProperties.getUrlSymmetricKey(), map);
    SymmetricDto data = new Gson().fromJson(new JsonParser().parse(result).getAsJsonObject().get("data"), SymmetricDto.class);
    LOGGER.debug("getSymmetricKey key={},rs={}", temail, data);
    return data.getSecretKey();
  }

  /**
   * [[对称]]加密
   */
  public byte[] symmetricEncrypt(String keyword, String text) {
    SymmetricCipher aesCipher = new AESCipher(keyword);
    return aesCipher.encrypt(text);
  }

  /**
   * [[对称]]解密
   */
  public String symmetricDecrypt(String keyword, byte[] encrypted) {
    SymmetricCipher aesCipher = new AESCipher(keyword);
    return aesCipher.decrypt(encrypted);
  }


  @Cacheable(value = "kms", key = "'ASYMMETRIC_KEY_PAIR' + #p0")
  public AsymmetricDto getAsymmetricKeypair(String temail) {
    Map map = new HashMap();
    map.put("text", temail);
    String result = post(kmsProperties.getUrlAsymmetricRegister(), map);
    AsymmetricDto dto = new Gson().fromJson(new JsonParser().parse(result).getAsJsonObject().get("data"), AsymmetricDto.class);
    return dto;
  }

  /**
   * TODO [非对称]签名
   */
  public String sign(String temail, String unsignText) {
    byte[] signed = vaultKeeper.asymmetricCipher(CipherAlgorithm.SM2).sign(temail, unsignText);
    return encoder(signed);
  }

  /**
   * TODO [非对称]验证
   */
  public boolean asymmetricVerify(String temail, String signed, String unsigned) {
    byte[] sign = decoder(signed);
    LOGGER.debug("getSymmetricKey temail={},signed={},unsigned={}", temail, signed, unsigned);
    return vaultKeeper.asymmetricCipher(CipherAlgorithm.SM2).verify(temail, unsigned, sign);
  }

  /**
   * TODO [非对称]加密
   */
  public String asymmetricEncrypt(String temail, String text) {
    byte[] bytes = vaultKeeper.asymmetricCipher(CipherAlgorithm.SM2).encrypt(temail, text);
    return encoder(bytes);
  }

  /**
   * TODO [非对称]解密
   */
  public String asymmetricDecrypt(String temail, String encrypted) {
    byte[] encryptBytes = decoder(encrypted);
    return vaultKeeper.asymmetricCipher(CipherAlgorithm.SM2).decrypt(temail, encryptBytes);
  }

  private byte[] decoder(String signed) {
    return Base64.getDecoder().decode(signed);
  }

  private String encoder(byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  String post(String url, Map map) {
    try {
      Gson gs = new Gson();
      String s = gs.toJson(map);
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
      HttpEntity<String> formEntity = new HttpEntity<String>(s, headers);
      String result = restTemplate.postForObject(url, formEntity, String.class);
      LOGGER.debug("TSBService-post->url=[{}],result=[{}]", url, result);
      return result;
    } catch (Exception e) {
      throw new KmsException("tsb service exception!", e);
    }
  }
}
