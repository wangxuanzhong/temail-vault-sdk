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

import static java.util.concurrent.TimeUnit.MICROSECONDS;
import static org.openjdk.jmh.annotations.Mode.AverageTime;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

public class BenchMark {

  @State(Scope.Benchmark)
  public static class ExecutionPlan {
    private final NativeAsymmetricCipher cipher = new NativeAsymmetricCipher();

    String privateKey;
    String publicKey;
    String plaintext;
    String encrypted;
    String signature;

    @Setup(Level.Invocation)
    public void setUp() {
      plaintext = "hello";
      publicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAt2ggdiOKuqbF8eaDGCcLKKe+ZAaTiSfqgyehR8g+i4CKj/RaqtMHVWjT67aXGMXmTczJwoJcn3ptXtUR7BxO0hgBXiXEXz7h8e4WCtmaeLSc/Be5flbzC5+W4X/vQsx88i8WMwqFih+k7ehvXMv1CSEWd+vKCFBMgRw3qbsSTUAducc=";
      privateKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBKV5D0MbnCjADQTiSnnFMX1UwlTwYOSDmDNU2ZLYoUq/a9BGG5gybmO3HCv+NKGZ6YuDwxxLMbF6k+mmPRXk0wjOhgYkDgYYABAC3aCB2I4q6psXx5oMYJwsop75kBpOJJ+qDJ6FHyD6LgIqP9Fqq0wdVaNPrtpcYxeZNzMnCglyfem1e1RHsHE7SGAFeJcRfPuHx7hYK2Zp4tJz8F7l+VvMLn5bhf+9CzHzyLxYzCoWKH6Tt6G9cy/UJIRZ368oIUEyBHDepuxJNQB25xw==";
      encrypted = "AAAAQwAAAEAAAAAQAAAABQIBFvru+HhsSZKhlml2OYDnmu/jGY2sD4P5zs4tx5u+veFJrTq1ieURFwwr3W5qpuNKVBxrava4D/pegIly9n3RQ8EQAJj8O7mRWAEBYWUFWwoUUdq2HBFn18PRHPLvaKZcvWAcylznDtOU2yj3+K50xAre1/eYk17PAODRHYFwNis6F4W/xYYl3B1+SC5AmdxxRw==";
      signature = "MIGHAkIAvElHZeHziY+xquNmkTI4K9sgPp5ys1Tdpwzw7a+PxfsFWSOpzB61R9GFDpp5ypKAu8Ryb+bFq7jQvKxrjLwFyo8CQQNT/LTjxSTQrG/yg5NdS8hKG1lViArECjZpiQycUTHJb05bph/qRXB4IwjHDwj7elQPEOrMg1Q5KJ/WTbFMmyGx";
    }
  }

  @Fork
  @Benchmark
  @BenchmarkMode(AverageTime)
  @OutputTimeUnit(MICROSECONDS)
  public void encrypt(ExecutionPlan plan, Blackhole blackhole) {
    blackhole.consume(plan.cipher.encrypt(plan.publicKey, plan.plaintext));
  }

  @Fork
  @Benchmark
  @BenchmarkMode(AverageTime)
  @OutputTimeUnit(MICROSECONDS)
  public void decrypt(ExecutionPlan plan, Blackhole blackhole) {
    blackhole.consume(plan.cipher.decrypt(plan.privateKey, plan.encrypted));
  }

  @Fork
  @Benchmark
  @BenchmarkMode(AverageTime)
  @OutputTimeUnit(MICROSECONDS)
  public void sign(ExecutionPlan plan, Blackhole blackhole) {
    blackhole.consume(plan.cipher.sign(plan.privateKey, plan.plaintext));
  }

  @Fork
  @Benchmark
  @BenchmarkMode(AverageTime)
  @OutputTimeUnit(MICROSECONDS)
  public void verify(ExecutionPlan plan, Blackhole blackhole) {
    blackhole.consume(plan.cipher.verify(plan.publicKey, plan.plaintext, plan.signature));
  }
}
