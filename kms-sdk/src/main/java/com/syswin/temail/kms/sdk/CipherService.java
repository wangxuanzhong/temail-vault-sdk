package com.syswin.temail.kms.sdk;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import com.syswin.temail.kms.sdk.dto.AsymmetricDto;
import com.syswin.temail.kms.sdk.dto.SymmetricDto;
import com.syswin.temail.kms.sdk.exception.KmsException;
import com.syswin.temail.kms.vault.CipherAlgorithm;
import com.syswin.temail.kms.vault.KeyAwareAsymmetricVaultKeeper;
import com.syswin.temail.kms.vault.aes.AESCipher;
import com.syswin.temail.kms.vault.aes.SymmetricCipher;
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
  public static final String TEXT = "text";
  public static final String ALGORITHM = "algorithm";
  public static final String AES = "AES";
  public static final String SM_2 = "SM2";
  public static final String ECDSA = "ECDSA";
  private final KmsProperties kmsProperties;
  private final RestTemplate restTemplate;
  private final KeyAwareAsymmetricVaultKeeper vaultKeeper;
  private final SymmetricCipher symmetricCipher = new AESCipher();

  public CipherService(KmsProperties kmsProperties, RestTemplate restTemplate, KeyAwareAsymmetricVaultKeeper vaultKeeper) {
    this.kmsProperties = kmsProperties;
    this.restTemplate = restTemplate;
    this.vaultKeeper = vaultKeeper;
  }

  /**
   * [[对称]]加密注册，返回秘钥
   */
  public String symmetricRegister(String temail) {
    Map map = new HashMap();
    map.put(TEXT, temail);
    map.put(ALGORITHM, AES);
    String result = post(kmsProperties.getUrlSymmetricRegister(), map);
    SymmetricDto data = new Gson().fromJson(new JsonParser().parse(result).getAsJsonObject().get("data"), SymmetricDto.class);
    return data.getSecretKey();
  }

  /**
   * [[对称]]加密算法的秘钥KEY
   */
  public String getSymmetricKey(String temail) {
    Map map = new HashMap();
    map.put(TEXT, temail);
    String result = post(kmsProperties.getUrlSymmetricKey(), map);
    SymmetricDto data = new Gson().fromJson(new JsonParser().parse(result).getAsJsonObject().get("data"), SymmetricDto.class);
    LOGGER.debug("getSymmetricKey key={},rs={}", temail, data);
    return data.getSecretKey();
  }

  /**
   * [[对称]]加密
   */
  public byte[] symmetricEncrypt(String keyword, String text) {
    return symmetricCipher.encrypt(keyword, text);
  }

  /**
   * [[对称]]解密
   */
  public String symmetricDecrypt(String keyword, byte[] encrypted) {
    return symmetricCipher.decrypt(keyword, encrypted);
  }

  /**
   * TODO [非对称]签名
   */
  public String sign(String temail, String unsignText) {
    return vaultKeeper.asymmetricCipher(CipherAlgorithm.ECDSA).sign(temail, unsignText);
  }

  /**
   * TODO [非对称]验证
   */
  public boolean asymmetricVerify(String temail, String unsigned, String signed) {
    LOGGER.debug("getSymmetricKey temail={},signed={},unsigned={}", temail, signed, unsigned);
    return vaultKeeper.asymmetricCipher(CipherAlgorithm.ECDSA).verify(temail, unsigned, signed);
  }

  /**
   * TODO [非对称]加密
   */
  public String asymmetricEncrypt(String temail, String text) {
    return vaultKeeper.asymmetricCipher(CipherAlgorithm.ECDSA).encrypt(temail, text);
  }

  /**
   * TODO [非对称]解密
   */
  public String asymmetricDecrypt(String temail, String encrypted) {
    return vaultKeeper.asymmetricCipher(CipherAlgorithm.ECDSA).decrypt(temail, encrypted);
  }

  @Cacheable(value = "kms", key = "'ASYMMETRIC_KEY_PAIR' + #p0")
  public AsymmetricDto asymmetricRegister(String temail) {
    Map map = new HashMap();
    map.put(TEXT, temail);
    map.put(ALGORITHM, ECDSA);
    String result = post(kmsProperties.getUrlAsymmetricRegister(), map);
    AsymmetricDto dto = new Gson().fromJson(new JsonParser().parse(result).getAsJsonObject().get("data"), AsymmetricDto.class);
    return dto;
  }

  @Cacheable(value = "kms", key = "'ASYMMETRIC_KEY_PAIR' + #p0")
  public AsymmetricDto getAsymmetricKeypair(String temail) {
    Map map = new HashMap();
    map.put(TEXT, temail);
    String result = post(kmsProperties.getUrlAsymmetricKey(), map);
    AsymmetricDto dto = new Gson().fromJson(new JsonParser().parse(result).getAsJsonObject().get("data"), AsymmetricDto.class);
    return dto;
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
