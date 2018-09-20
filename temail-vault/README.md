# Vault SDK

当前SDK jar包只支持Linux运行环境，其他环境须自行编译C++算法源码。

## 使用步骤
1. 引入依赖
```
    <groupId>com.syswin.temail</groupId>
    <artifactId>vault-keeper</artifactId>
    <version>x.x.x</version>
```
1. 使用 `VaultKeeper` 获取算法，当前只支持 `ECDSA` ，使用算法前须注册账户， `VaultKeeper` 会自动管理用户密证。
```java
  KeyAwareAsymmetricCipher cipher = new VaultKeeper().asymmetricCipher(CipherAlgorithm.ECDSA);

  byte[] publicKey = cipher.register("sean@t.email");
  cipher.encrypt("sean@t.email", "hello world");
  // ...
```
