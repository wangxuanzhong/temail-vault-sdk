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
### *nux编译步骤
1. 运行 `mvn package -DskipTests`

### Windows编译步骤
1. 安装 `GitBash`
1. 安装 `Mingw64`
1. 安装 [`Perl`](http://strawberryperl.com/)
1. 下载 [`OpenSSL`](https://www.openssl.org/)
1. 在 `GitBash` 中编译 `OpenSSL`
  ```
  export PATH=$PATH:<mingw64 folder>/bin
  perl Configure mingw64 no-shared no-asm --prefix=/C/OpenSSL-x64
  mingw32-make.exe depend
  mingw32-make.exe
  mingw32-make.exe install
  ```
完成以上安装步骤后，运行 `mvn package -DskipTests`

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
