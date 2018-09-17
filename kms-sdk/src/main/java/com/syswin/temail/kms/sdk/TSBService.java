package com.syswin.temail.kms.sdk;

import com.google.gson.Gson;
import com.syswin.temail.kms.sdk.exception.KmsException;
import com.syswin.temail.kms.vault.aes.AESCipher;
import com.syswin.temail.kms.vault.aes.SymmetricCipher;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

public class TSBService {

  private static final Logger LOGGER = LoggerFactory.getLogger(TSBService.class);
  @Autowired
  private KmsProperties kmsProperties;

  @Autowired
  private RestTemplate restTemplate;

  /**
   * [[对称]]加密注册，返回秘钥
   */
  public String symmetricRegister(String temail) {
    Map map = new HashMap();
    map.put("text", temail);
    String result = post(kmsProperties.getUrlSymmetricRegister(), map);
    Gson gs = new Gson();
    ResultDto resultDto = gs.fromJson(result, ResultDto.class);
    return resultDto.getData().toString();
  }

  /**
   * [[对称]]加密算法的秘钥KEY
   */
  @Cacheable(value = "kms", key = "'SYMMETRIC_KEY_' + #p0")
  public String getSymmetricKey(String temail) {
    Map map = new HashMap();
    map.put("text", temail);
    String result = post(kmsProperties.getUrlSymmetricKey(), map);
    Gson gs = new Gson();
    ResultDto resultDto = gs.fromJson(result, ResultDto.class);
    String rs = resultDto.getData().toString();
    LOGGER.debug("getSymmetricKey key={},rs={}", temail, rs);
    return rs;
  }

  /**
   * [[对称]]加密
   */
  public String symmetricEncrypt(String keyword, String text) {
    SymmetricCipher aesCipher = new AESCipher(keyword);
    return aesCipher.encrypt(text);
  }

  /**
   * [[对称]]解密
   */
  public String symmetricDecrypt(String keyword, String encrypted) {
    SymmetricCipher aesCipher = new AESCipher(keyword);
    return aesCipher.decrypt(encrypted);
  }


  /**
   * [非对称]加密注册，返回公钥
   */
  @Cacheable(value = "kms", key = "'ASYMMETRIC_KEY_' + #p0")
  public String asymmetricRegister(String text) {
    Map map = new HashMap();
    map.put("text", text);
    String result = post(kmsProperties.getUrlAsymmetricRegister(), map);
    Gson gs = new Gson();
    ResultDto resultDto = gs.fromJson(result, ResultDto.class);
    String rs = resultDto.getData().toString();
    LOGGER.debug("getSymmetricKey key={},rs={}", text, rs);
    return rs;
  }

  /**
   * TODO [非对称]签名
   */
  public String sign(String temail, String text) {
    Map map = new HashMap();
    map.put("temail", temail);
    map.put("text", text);
    return "";
  }


  /**
   * TODO [非对称]验证
   */
  @Cacheable(value = "kms", key = "'ASYMMETRIC_VERIFY_' + #p0 + '_' + #p1")
  public boolean asymmetricVerify(String temail, String signed) {
    Map map = new HashMap();
    map.put("temail", temail);
    map.put("text", signed);
    LOGGER.debug("getSymmetricKey temail={},signed={}", temail, signed);
    return false;
  }

  /**
   * TODO [非对称]公钥
   */
  public String getAsymmetricPubKey(String temail, String text) {
    Map map = new HashMap();
    map.put("temail", temail);
    map.put("text", text);
    String result = get(kmsProperties.getUrlAsymmetricKey(), map);
    Gson gs = new Gson();
    ResultDto resultDto = gs.fromJson(result, ResultDto.class);
    return resultDto.getData().toString();
  }

  /**
   * TODO [非对称]加密
   */
  public String asymmetricEncrypt(String keyword, String text) {
    return text;
  }

  /**
   * TODO [非对称]解密
   */
  public String asymmetricDecrypt(String keyword, String encrypted) {
    return encrypted;
  }

  private String post(String url, Map map) {
    try {
      Gson gs = new Gson();
      String s = gs.toJson(map);
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
      HttpEntity<String> formEntity = new HttpEntity<String>(s, headers);
      String result = restTemplate.postForObject(url, formEntity, String.class);
      LOGGER.debug("TSBService-->url=[{}],result=[{}]", url, result);
      return result;
    } catch (Exception e) {
      throw new KmsException("tsb service exception!", e);
    }
  }

  private String get(String url, Map map) {
    try {
      Iterator<String> it = map.keySet().iterator();
      StringBuffer stringBuffer = new StringBuffer();
      while (it.hasNext()) {
        String key = it.next();
        stringBuffer.append(key).append("={").append(key).append("}&");
      }
      if (stringBuffer.length() > 0) {
        url += "?" + stringBuffer.toString().substring(0, stringBuffer.length() - 1);
      }
      String result = restTemplate.getForObject(url, String.class, map);
      LOGGER.debug("TSBService-->url=[{}],result=[{}]", url, result);
      return result;
    } catch (Exception e) {
      throw new KmsException("tsb service exception!", e);
    }
  }
}
