# Vault SDK

## 运行前置要求
* 创建SDK C++库存放文件夹
```
mkdir -p /tmp/vault
```

* 配置SDK环境变量
```
export VAULT_NATIVE_DIR=/tmp/vault
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${VAULT_NATIVE_DIR}
```  

* JAVA应用运行参数设置 `temail.vault.native.workdir`
```
java -Dtemail.vault.native.workdir=${VAULT_NATIVE_DIR} -jar <application>.jar <Main Class>
```

## FAQ
### libecc.so: 无法打开共享对象文件: 没有那个文件或目录

如出现以下异常，请确认已先创建SDK C++库存放文件夹，并按以上步骤配置启动参数。
```
Exception in thread "main" java.lang.UnsatisfiedLinkError: /tmp/vault/libVault.so: libecc.so: 无法打开共享对象文件: 没有那个文件或目录
	at java.lang.ClassLoader$NativeLibrary.load(Native Method)
	at java.lang.ClassLoader.loadLibrary0(ClassLoader.java:1941)
	at java.lang.ClassLoader.loadLibrary(ClassLoader.java:1824)
	at java.lang.Runtime.load0(Runtime.java:809)
	at java.lang.System.load(System.java:1086)
	at com.syswin.temail.vault.jni.NativeUtils.loadLibraryFromJar(NativeUtils.java:106)
	at com.syswin.temail.vault.jni.CipherJni.<clinit>(CipherJni.java:10)
	at com.syswin.temail.kms.vault.NativeAsymmetricCipher.<init>(NativeAsymmetricCipher.java:17)
```

### java: symbol lookup error
如出现以下异常，说明C++动态库与当前环境不兼容，需要另行编译。
```
java: symbol lookup error: /tmp/vaultJni/libVault.so: undefined symbol: _ZN3ECC15ecc_generateKeyERNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES6_
```
