package com.syswin.temail.kms.vault;

import static com.seanyinx.github.unit.scaffolding.AssertUtils.expectFailing;
import static org.assertj.core.api.Assertions.assertThat;

import com.syswin.temail.kms.vault.exceptions.VaultCipherException;
import org.junit.Ignore;
import org.junit.Test;

@Ignore
public class NativeAsymmetricCipherTest {

  private final NativeAsymmetricCipher cipher = new NativeAsymmetricCipher();
  private final KeyPair keyPair = cipher.getKeyPair();
  private final String plaintext = "Sean";
  private final String publicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAt2ggdiOKuqbF8eaDGCcLKKe+ZAaTiSfqgyehR8g+i4CKj/RaqtMHVWjT67aXGMXmTczJwoJcn3ptXtUR7BxO0hgBXiXEXz7h8e4WCtmaeLSc/Be5flbzC5+W4X/vQsx88i8WMwqFih+k7ehvXMv1CSEWd+vKCFBMgRw3qbsSTUAducc=";
  private final String privateKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBKV5D0MbnCjADQTiSnnFMX1UwlTwYOSDmDNU2ZLYoUq/a9BGG5gybmO3HCv+NKGZ6YuDwxxLMbF6k+mmPRXk0wjOhgYkDgYYABAC3aCB2I4q6psXx5oMYJwsop75kBpOJJ+qDJ6FHyD6LgIqP9Fqq0wdVaNPrtpcYxeZNzMnCglyfem1e1RHsHE7SGAFeJcRfPuHx7hYK2Zp4tJz8F7l+VvMLn5bhf+9CzHzyLxYzCoWKH6Tt6G9cy/UJIRZ368oIUEyBHDepuxJNQB25xw==";

  @Test
  public void shouldGenerateKeyPair() {
    assertThat(keyPair.getPublic()).isNotNull();
    assertThat(keyPair.getPrivate()).isNotNull();
  }

  @Test
  public void shouldEncrypt() {
    String encrypted = cipher.encrypt(keyPair.getPublic(), plaintext);
    assertThat(encrypted).isNotNull();

    String plaintext = cipher.decrypt(keyPair.getPrivate(), encrypted);
    assertThat(plaintext).isEqualTo(this.plaintext);
  }

  @Test
  public void shouldFailEncryption() {
    try {
      cipher.encrypt("blah", plaintext);
      expectFailing(VaultCipherException.class);
    } catch (VaultCipherException e) {
      assertThat(e).hasMessage("Invalid public or private key");
    }
  }

  @Test
  public void shouldSign() {
    String signature = cipher.sign(keyPair.getPrivate(), plaintext);
    assertThat(signature).isNotNull();

    boolean verified = cipher.verify(keyPair.getPublic(), plaintext, signature);
    assertThat(verified).isTrue();

    verified = cipher.verify(keyPair.getPublic(), "Jack", signature);
    assertThat(verified).isFalse();
  }

  @Test
  public void encryptWithPublicKey() {
    String encrypted = cipher.encrypt(publicKey, plaintext);
    String plaintext = cipher.decrypt(privateKey, encrypted);

    assertThat(plaintext).isEqualTo(this.plaintext);
  }

  @Test
  public void decryptWithPrivateKey() {
    String encrypted = "AAAAQwAAAEAAAAAQAAAABQIBFvru+HhsSZKhlml2OYDnmu/jGY2sD4P5zs4tx5u+veFJrTq1ieURFwwr3W5qpuNKVBxrava4D/pegIly9n3RQ8EQAJj8O7mRWAEBYWUFWwoUUdq2HBFn18PRHPLvaKZcvWAcylznDtOU2yj3+K50xAre1/eYk17PAODRHYFwNis6F4W/xYYl3B1+SC5AmdxxRw==";
    String plaintext = cipher.decrypt(privateKey, encrypted);

    assertThat(plaintext).isEqualTo("hello");
  }

  @Test
  public void signWithPrivateKey() {
    String signature = cipher.sign(privateKey, plaintext);
    boolean verified = cipher.verify(publicKey, plaintext, signature);

    assertThat(verified).isTrue();
  }

  @Test
  public void verifyWithPublicKey() {
    String signature = "MIGHAkIAvElHZeHziY+xquNmkTI4K9sgPp5ys1Tdpwzw7a+PxfsFWSOpzB61R9GFDpp5ypKAu8Ryb+bFq7jQvKxrjLwFyo8CQQNT/LTjxSTQrG/yg5NdS8hKG1lViArECjZpiQycUTHJb05bph/qRXB4IwjHDwj7elQPEOrMg1Q5KJ/WTbFMmyGx";
    boolean verified = cipher.verify(publicKey, "hello", signature);

    assertThat(verified).isTrue();
  }
}
