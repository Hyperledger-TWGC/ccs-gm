# ccs-gm
go语言国密密码库，实现了数据签名/验签、数据哈希、对称加密、非对称加密、x509证书管理、以及国密tls通信的功能。

[![Build Status](https://travis-ci.com/Hyperledger-TWGC/ccs-gm.svg?branch=master)](https://travis-ci.com/Hyperledger-TWGC/ccs-gm)
![Go](https://github.com/Hyperledger-TWGC/ccs-gm/workflows/Go/badge.svg?branch=master)
[![Build Status](https://dev.azure.com/Hyperledger/TWGC/_apis/build/status/Hyperledger-TWGC.ccs-gm?branchName=master)](https://dev.azure.com/Hyperledger/TWGC/_build/latest?definitionId=126&branchName=master)

## License
Hyperledger Project source code files are made available under the Apache License, Version 2.0 (Apache-2.0), located in the [LICENSE](LICENSE) file.

## Feature 功能支持列表

|  SM2功能   | 支持范围  | 
|  ----  | ----  |
| Generate KeyPair  | 是 |
| Sign  | 是 |
| Verify | 是 |
| PEM格式导出 | 私钥/公钥/证书|
| PEM格式导入 | 私钥/公钥/证书 |
| PEM文件加密 | RFC5958 |  

|  SM4功能   | 支持范围  | 
|  ----  | ----  |
| Generate Key | 是 |
| Encrypt, Decrypt | 是 |
| PEM格式导出 |   |
| PEM文件加密 | golang: `x509.EncryptPEMBlock` |
| 分组模式 | ECB/CBC |


|  SM3功能   | 支持范围  | 
|  ----  | ----  |
| 当前语言Hash接口兼容 | `是` |

