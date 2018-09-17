package m.syswin.temail.kms.sdk.test;

import com.syswin.temail.kms.sdk.KmsProperties;
import com.syswin.temail.kms.sdk.TSBService;
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

  @Override
  public void run(String... args) {

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

    String eccTemail = "ecctemail" + (System.currentTimeMillis()) + "@temail.com";
    //sdk ecc注册
    String eccText = "this is a text";
    String signature = itsbService.asymmetricRegister(eccTemail);
    System.out.println("asymmetricRegister : " + signature);
    //验证
    boolean verifyResult1 = itsbService.asymmetricVerify(eccTemail, eccText);
    System.out.println("asymmetricVerifyResult : " + verifyResult1);
    boolean verifyResult2 = itsbService.asymmetricVerify(eccTemail, eccText);
    System.out.println("asymmetricVerifyResult : " + verifyResult2);
    Assert.assertEquals(verifyResult1, verifyResult2);
    //获取公私钥对
    String asymmetricKey = itsbService.getAsymmetricPubKey(eccTemail);
    System.out.println("asymmetricKey : " + asymmetricKey);
    Assert.assertEquals(signature, asymmetricKey);

//    //签名
//    String signatureStr = itsbService.sign(eccTemail, eccText);
//    System.out.println("signatureStr : " + signatureStr);
//    //验签
//    boolean checkSignResult = itsbService.checkSign(eccTemail, eccText);
//    System.out.println("checkSignResult : " + checkSignResult);
    System.exit(0);
  }
}
