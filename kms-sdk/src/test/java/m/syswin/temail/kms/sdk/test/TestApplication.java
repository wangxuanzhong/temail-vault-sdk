package com.syswin.temail.kms.sdk.test;

import com.syswin.temail.kms.sdk.KmsProperties;
import com.syswin.temail.kms.sdk.TSBService;
import com.syswin.temail.kms.vault.KeyPair;
import com.syswin.temail.kms.vault.cache.ICache;
import org.junit.Assert;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TestApplication implements CommandLineRunner {

  public static void main(String[] args) {
    SpringApplication.run(TestApplication.class, args);
  }

  @Autowired
  TSBService itsbService;

  @Autowired
  KmsProperties kmsProperties;
  @Autowired
  private ICache cache;

  @Override
  public void run(String... args) {
    String key = "key";
    KeyPair keyPair = new KeyPair("privateKey".getBytes(), "pubKey".getBytes());
    cache.put(key, keyPair);
    KeyPair keyPair1 = cache.get(key);
    Assert.assertEquals(new String(keyPair1.getPrivate()), "privateKey");
    Assert.assertEquals(new String(keyPair1.getPublic()), "pubKey");
    System.out.println("cache OK");
    System.out.println("-------------------------------");
    //temail aes注册
    String temail = "milk" + (System.currentTimeMillis()) + "@temail.com";
    String encrypted = itsbService.symmetricRegister(temail);
    System.out.println("symmetricRegister : " + encrypted);
    //获取密钥
    String symmetricKey1 = itsbService.getSymmetricKey(temail);
    System.out.println("symmetricKey : " + symmetricKey1);

    String symmetricKey2 = itsbService.getSymmetricKey(temail);
    System.out.println("symmetricKey : " + symmetricKey2);
    Assert.assertEquals(symmetricKey1, symmetricKey2);

    String text = "milk@t.email中国人";
    //加密
    String encryptedStr = itsbService.symmetricEncrypt(symmetricKey1, text);
    System.out.println("encryptedStr : " + encryptedStr);
    //解密
    String decryptedStr = itsbService.symmetricDecrypt(symmetricKey1, encryptedStr);
    System.out.println("decryptedStr : " + decryptedStr);
    Assert.assertEquals(text, decryptedStr);
    System.out.println("-------------------------------");
    String eccTemail = "ecctemail" + (System.currentTimeMillis()) + "@temail.com";
    //sdk ecc注册
    String unsign = "this is a text";
    String signature = itsbService.asymmetricRegister(eccTemail);
    System.out.println("asymmetricRegister : " + signature);
//    //签名
//    String sign = itsbService.sign(eccTemail, unsign);
//    System.out.println("signatureStr : " + sign);
//    //验证
//    boolean verifyResult1 = itsbService.asymmetricVerify(eccTemail, unsign, sign);
//    System.out.println("asymmetricVerifyResult : " + verifyResult1);
//    boolean verifyResult2 = itsbService.asymmetricVerify(eccTemail, unsign, sign);
//    System.out.println("asymmetricVerifyResult : " + verifyResult2);
//    Assert.assertEquals(verifyResult1, verifyResult2);
    //获取公私钥对
    String asymmetricKey = itsbService.getAsymmetricPubKey(eccTemail);
    System.out.println("asymmetricKey : " + asymmetricKey);
    Assert.assertEquals(signature, asymmetricKey);

    String txt = itsbService.asymmetricEncrypt(eccTemail, unsign);
    String a = itsbService.asymmetricDecrypt(eccTemail, txt);
    Assert.assertEquals(a, unsign);

    //签名
    String sign = itsbService.sign(eccTemail, unsign);
    System.out.println("signatureStr : " + sign);
    //验证
    boolean verifyResult1 = itsbService.asymmetricVerify(eccTemail, unsign, sign);
    System.out.println("asymmetricVerifyResult : " + verifyResult1);
    boolean verifyResult2 = itsbService.asymmetricVerify(eccTemail, unsign, sign);
    System.out.println("asymmetricVerifyResult : " + verifyResult2);
    Assert.assertEquals(verifyResult1, verifyResult2);

    System.exit(0);
  }
}
