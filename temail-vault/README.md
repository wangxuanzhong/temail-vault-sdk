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
1. 切换到 `windows` 代码分支
1. 安装 `Mingw64`，选择版本 x86_64-8.1.0-posix-seh-rt_v6-rev0
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

### Mac编译安装
* 安装 `openssl`
编译时，需要openssl
```
brew install openssl
```

## FAQ
### C++ 编译器版本过低
错误信息：
```
/lib64/libstdc++.so.6: version `GLIBCXX_3.4.15' not found (required by /tmp/vault2589851008846924/libVault.so)
```
    
需要安装 `gcc-4.9.2`
按以下方式安装
* CentOS YUM源安装 `yum install -y libgcc`
* 源码安装
```
wget http://ftp.gnu.org/gnu/gcc/gcc-4.9.2/gcc-4.9.2.tar.gz
tar xvzf gcc-4.9.2.tar.gz
cd gcc-4.9.2
yum install gmp-devel mpfr-devel libmpc-devel -y
./configure --enable-languages=c,c++ --disable-multilib
make -j$(nproc) && make install
```

### C++ LINKER版本过低
如需编译C++算法源码，需安装 `ld-2.27` 及 `libuuid-devel`
* 安装 `libuuid` 
```
yum -y install libuuid-devel
```

* 安装 `ld-2.27`
```
yum install binutils
```

### Windows上找不到 `mutex` 或 `__imp___acrt_iob_func`
错误信息:
```
temail-vault-sdk\temail-vault\libecc\src\main\c++\ALG\src\ecc\ecc.cpp:12:6: error: 'mutex' in namespace 'std' does not name a type
 std::mutex g_eccKeyMut;
      ^~~~~
temail-vault-sdk\temail-vault\libecc\src\main\c++\ALG\src\ecc\ecc.cpp:90:36: error: 'g_eccKeyMut' was not declared in this scope
  std::unique_lock<std::mutex> lock(g_eccKeyMut);
                                    ^~~~~~~~~~~
```

```
c:/OpenSSL-x64/lib/libcrypto.a(e_capi.o):e_capi.c:(.text+0x3670): undefined reference to `__imp___acrt_iob_func'
c:/OpenSSL-x64/lib/libcrypto.a(eng_openssl.o):eng_openssl.c:(.text+0x10): undefined reference to `__imp___acrt_iob_func'
c:/OpenSSL-x64/lib/libcrypto.a(eng_openssl.o):eng_openssl.c:(.text+0x424): undefined reference to `__imp___acrt_iob_func'
c:/OpenSSL-x64/lib/libcrypto.a(ui_openssl.o):ui_openssl.c:(.text+0x19): undefined reference to `__imp___acrt_iob_func'
c:/OpenSSL-x64/lib/libcrypto.a(ui_openssl.o):ui_openssl.c:(.text+0x759): undefined reference to `__imp___acrt_iob_func'
c:/OpenSSL-x64/lib/libcrypto.a(ui_openssl.o):ui_openssl.c:(.text+0x7aa): more undefined references to `__imp___acrt_iob_func' follow
collect2.exe: error: ld returned 1 exit status
```

解决办法：使用如下mingw64 g++编译器
```
$ g++ -v
Using built-in specs.
COLLECT_GCC=E:\mingw-w64\x86_64-8.1.0-posix-seh-rt_v6-rev0\mingw64\bin\g++.exe
```
