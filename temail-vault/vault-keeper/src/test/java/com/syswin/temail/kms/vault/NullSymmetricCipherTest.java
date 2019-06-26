/*
 * MIT License
 *
 * Copyright (c) 2019 Syswin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.syswin.temail.kms.vault;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;

public class NullSymmetricCipherTest {

  private final NullSymmetricCipher cipher = new NullSymmetricCipher();

  @Test
  public void emptyKey() {
    String key = cipher.getKey("hello");

    assertThat(key).isEmpty();
  }

  @Test
  public void encryptionDoesNothing() {
    String plaintext = "plaintext";
    String encrypted = cipher.encrypt("hello", plaintext);

    assertThat(encrypted).isEqualTo(plaintext);
  }

  @Test
  public void decryptionDoesNothing() {
    String encrypted = "encrypted";
    String plaintext = cipher.decrypt("hello", encrypted);

    assertThat(plaintext).isEqualTo(encrypted);
  }
}