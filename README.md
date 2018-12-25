## 密基Java版
封装C++密基

具体使用方法请见 `temail-vault/README.md`

### 使用Benchmark测试密基算法性能
运行如下命令打包
```
mvn package
```

运行如下命令开始性能测试
```
java -cp dependency/*:vault-keeper-1.0.8-SNAPSHOT-tests.jar:vault-keeper-1.0.8-SNAPSHOT.jar com.syswin.temail.kms.vault.BenchmarkRunner
```

示例性能测试结果数据
```
Benchmark          Mode  Cnt     Score      Error  Units
BenchMark.decrypt  avgt  200  9088.184 ±   34.702  us/op
BenchMark.encrypt  avgt  200  9488.350 ±   32.648  us/op
BenchMark.sign     avgt  200  2526.902 ±  510.948  us/op
BenchMark.verify   avgt  200  2872.475 ± 1015.743  us/op```
