# go-pixiv

Bypass SNI censorship on Pixiv with golang

golang隐藏SNI绕过对Pixiv的SNI封锁

## Installation

### 下载二进制文件
从[发布页](https://github.com/eternal-flame-AD/go-pixiv/releases)下载最新二进制build
### 从源码编译
```bash
go get -u -v github.com/eternal-flame-AD/go-pixiv
```

## Usage

1. 在计算机上安装[这个CA证书](https://github.com/eternal-flame-AD/goproxy/raw/master/ca.pem)(右键另存为)，安装方法自行百度（帮你百度好了[Chrome](https://jingyan.baidu.com/article/c843ea0bc4142a77921e4a79.html)和[Firefox](https://jingyan.baidu.com/article/4e5b3e191205d291911e2463.html)的）
2. 设置浏览器代理为 http://127.0.0.1:8080 ，方法参见上一步，**注意HTTPS也要走代理(勾选“对以下协议使用相同代理”)**
3. 运行go-pixiv，浏览器应该会自动打开一个诊断窗口，检查浏览器的代理和证书信任配置是否正确，DNS能否正常工作。
4. OK

## Troubleshooting

- `Proxy is not enabled, please set your local proxy to http://127.0.0.1:8080/` 未设置浏览器代理
- `CA Trust: Error` 浏览器不信任Go-Pixiv使用的证书，检查Usage中第一步是否正确，注意Firefox有自己的keychain
- `DNS-Over-Https: Error` 部分域名未能解析到可用的IP地址，解析正常的域名可以继续访问。如果遇到全部错误的情况，可能是你的网络封禁了1.0.0.1