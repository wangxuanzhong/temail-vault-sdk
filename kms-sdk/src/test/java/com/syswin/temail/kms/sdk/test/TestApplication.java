package com.syswin.temail.kms.sdk.test;

import static com.syswin.temail.kms.vault.CipherAlgorithm.ECDSA;

import com.syswin.temail.kms.vault.KeyAwareVault;
import java.util.Optional;
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
  private KeyAwareVault vault;

  @Override
  public void run(String... args) {
    //temail aes注册
    String temail = "milk" + (System.currentTimeMillis()) + "@temail.com";
    String symmetricKey = vault.symmetricCipher().getKey(temail);

    String text = "milk@t.email中国人";
    //加密
    String encryptedStr = vault.symmetricCipher().encrypt(symmetricKey, text);
    System.out.println("encryptedStr : " + encryptedStr);
    //解密
    String decryptedStr = vault.symmetricCipher().decrypt(symmetricKey, encryptedStr);
    System.out.println("decryptedStr : " + decryptedStr);
    Assert.assertEquals(text, decryptedStr);
    System.out.println("-------------------------------");
    String eccTemail = "ecctemail" + (System.currentTimeMillis()) + "@temail.com";
    //sdk ecc注册
    String unsign = "this is a text";
    String signature = vault.asymmetricCipher(ECDSA).register(eccTemail);
    System.out.println("asymmetricRegister : " + signature);
    //获取公私钥对
    Optional<String> asymmetricKey = vault.asymmetricCipher(ECDSA).publicKey(eccTemail);
    System.out.println("asymmetricKey : " + asymmetricKey);
    Assert.assertEquals(signature, asymmetricKey.get());

    String txt = vault.asymmetricCipher(ECDSA).encrypt(eccTemail, unsign);
    String a = vault.asymmetricCipher(ECDSA).decrypt(eccTemail, txt);
    Assert.assertEquals(a, unsign);

    //签名
    String sign = vault.asymmetricCipher(ECDSA).sign(eccTemail, unsign);
    System.out.println("signatureStr : " + sign);
    //验证
    boolean verifyResult1 = vault.asymmetricCipher(ECDSA).verify(eccTemail, unsign, sign);
    System.out.println("asymmetricVerifyResult : " + verifyResult1);
    boolean verifyResult2 = vault.asymmetricCipher(ECDSA).verify(eccTemail, unsign, sign);
    System.out.println("asymmetricVerifyResult : " + verifyResult2);
    Assert.assertEquals(verifyResult1, verifyResult2);
  }
}
