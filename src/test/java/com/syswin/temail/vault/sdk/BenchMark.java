package com.syswin.temail.vault.sdk;

import static com.syswin.temail.vault.sdk.VaultSdk.Algorithm.ECC;
import static java.util.concurrent.TimeUnit.MICROSECONDS;
import static org.openjdk.jmh.annotations.Mode.AverageTime;

import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.infra.Blackhole;

public class BenchMark {

  private static final String temail = "sean@t.email";
  private final String plainText = "hello world";

  @State(Scope.Benchmark)
  public static class ExecutionPlan {

    private VaultSdk vaultSdk;

    @Setup(Level.Invocation)
    public void setUp() {
      final String backupDir = System.getProperty("java.io.tmpdir") + "vault-sdk";
      vaultSdk = VaultSdk.getInstance();
      vaultSdk.withBackupDir(backupDir);
    }
  }

  @Fork
  @org.openjdk.jmh.annotations.Benchmark
  @BenchmarkMode(AverageTime)
  @OutputTimeUnit(MICROSECONDS)
  public void generatePublicKey(ExecutionPlan plan, Blackhole blackhole) {
    blackhole.consume(plan.vaultSdk.generatePublicKey(ECC, temail));
  }

  @Fork
  @org.openjdk.jmh.annotations.Benchmark
  @BenchmarkMode(AverageTime)
  @OutputTimeUnit(MICROSECONDS)
  public void encryption(ExecutionPlan plan, Blackhole blackhole) {
    blackhole.consume(plan.vaultSdk.encrypt(ECC, temail, plainText));
  }

  @Fork
  @org.openjdk.jmh.annotations.Benchmark
  @BenchmarkMode(AverageTime)
  @OutputTimeUnit(MICROSECONDS)
  public void sign(ExecutionPlan plan, Blackhole blackhole) {
    blackhole.consume(plan.vaultSdk.sign(ECC, temail, plainText));
  }
}
