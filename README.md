# SM3

国家商用密码算法SM3，采用纯Python与C扩展实现。

## 主要功能

* SM3 Hash。
* SM3 HMac。

## 安装方法
1. 执行 pip3 wheel . 构建版本包；
2. 执行 pip install sm3-x.x.x-cpxxx-cpxxx-xxx.whl 安装

## 使用样例
```
from os import urandom
from sm3 import sm3_hash, sm3_hmac

data = urandom(200)
salt = urandom(128)

print(sm3_hash(data).hex())
print(sm3_hmac(salt, data).hex())


```
