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
  // 使用VaultKeeper须传入租户ID (例如syswin)，当前租户ID未生效，后续须先注册为合法租户方可使用SDK
  KeyAwareAsymmetricCipher cipher = new VaultKeeper("syswin").asymmetricCipher(CipherAlgorithm.ECDSA);

  byte[] publicKey = cipher.register("sean@t.email");
  cipher.encrypt("sean@t.email", "hello world");
  // ...
```
1. 添加环境变量
```
export JAVA_HOME=/usr/local/jdk1.8.0_161
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib:/usr/local/lib64:/usr/lib64
```

## 本地测试
**注意：当前本地测试只支持LINUX和MAC**

1. 注释 `vault-native/pom.xml` 中以下行
```
<linkerEndOption>-luuid</linkerEndOption>
```
1. 运行 `mvn package -DskipTests`
1. 将 `libecc.dylib` 放入 `/usr/local/lib` 

## FAQ
### C++ 编译器版本过低
错误信息：
```
/lib64/libstdc++.so.6: version `GLIBCXX_3.4.21' not found (required by /tmp/vault2589851008846924/libVault.so)
```
    
需要安装 `gcc-5.4.0`
```
curl https://ftp.gnu.org/gnu/gcc/gcc-5.4.0/gcc-5.4.0.tar.bz2 -O
tar xvfj gcc-5.4.0.tar.bz2
cd gcc-5.4.0
yum install gmp-devel mpfr-devel libmpc-devel -y
./configure --enable-languages=c,c++ --disable-multilib
make -j$(nproc) && make install
```

### C++ LINKER版本过低
如需编译C++算法源码，需安装 `ld-2.31` 及 `libuuid-devel`
* 安装 `libuuid` 
```
yum -y install libuuid-devel
```

* 安装 `ld`
```
wget https://mirrors.tuna.tsinghua.edu.cn/gnu/binutils/binutils-2.31.tar.gz
tar xzvf binutils-2.31.tar.gz
cd binutils-2.31
./configure --enable-languages=c,c++ --disable-multilib
make -j$(nproc) && make install
```
