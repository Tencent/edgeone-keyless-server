[English](readme.md) | 中文
# Edgeone keyless server

基于trpc-go框架开发的工具，支持在SSL握手认证过程中独立部署私钥，从而确保私钥的更高安全性。它还支持以下功能:
```
1. 支持双向认证（与握手节点的双向认证）
2. 支持多种证书类型的双向认证（RSA，ECC）
3. 支持公钥和私钥证书的热加载（作为建立SSL握手节点的公钥和私钥证书）
4. 支持远程认证证书类型（RSA）
5. 支持简单的配置管理服务，如证书、IP、端口、日志等
6. 支持查看当前实际访问性能参数（QPS、次数、平均耗时等）

```

## 快速开始

### 准备工作

- **[Go](https://go.dev/doc/install)**, 版本应大于或等于go1.18。
- **[tRPC cmdline tools](https://github.com/trpc-group/trpc-cmdline)**, 用于生成PB(protobuf)协议代码
- **[trpc-go](https://github.com/trpc-group/trpc-go)**, 版本为v1.0.3
- **[Openssl](https://github.com/openssl/openssl?tab=readme-ov-file#build-and-install)**, 需要相关库openssl-static 、openssl-devel 和zlib-devel
    ```bash
    #On Centos:
    sudo yum install openssl-static -y
    sudo yum install openssl-devel -y
    sudo yum install zlib-devel -y
    ```
    ```
    #On Debian-based Linuxes:
    sudo apt-get install openssl-static
    sudo apt-get install openssl-devel 
    sudo apt-get install zlib-devel
    ```
### 安装

源码编译即可运行，后续可以提供rpm包来支持直接安装

## 获取源码
```
git clone https://github.com/tencent/edgeone-keyless-server.git
cd edgeone-keyless-server
```
### 执行示例

1.编译并执行服务端代码,相关配置已经在trpc_go.yaml配置完毕
```
go build -o keyless main.go
chmod a+x keyless
./keyless
```
2.trpc_go.yaml配置说明
```
server:  # 服务端配置
  service:  # 具体业务服务配置
    - name: trpc.app.server.keylessHTTP # 本地访问(可选),方便本地重载边缘认证的证书(非双向认证的证书)
      protocol: http  # 应用层协议 trpc http
      ip: 127.0.0.1
      port: 8080
    - name: trpc.app.server.keylessHTTPSMutual
      timeout: 10000  # 单位 ms，每个接收到的请求最多允许 1000ms 的执行时间，所以要注意权衡当前请求内的所有串行 RPC 调用的超时时间分配，默认为 0，不设置超时
      protocol: http  # 应用层协议 trpc http
      ip: x.x.x.x  # 绑定对外服务的ip
      port: 443  # ssl默认端口
      tls_cert: "/your_keyless_path/mutual_ssl/yourcert.crt"  # 公钥
      tls_key: "/your_keyless_path/mutual_ssl/yourprivatecert.key"  # 私钥
      ca_cert: "/your_keyless_path/mutual_ssl/yourca.pem"  # CA证书，如果需要双向认证就必须配置
plugins:
  log:  # 所有日志配置
    default:  # 默认日志配置，log.Debug("xxx")
      - writer: console  # 控制台标准输出 默认
        level: debug  # 标准输出日志的级别
    custom:  # 默认日志配置，log.Debug("xxx")
      - writer: console  # 控制台标准输出 默认
        level: debug  # 标准输出日志的级别
      - writer: file  # 本地文件日志
        level: debug  # 本地文件滚动日志的级别
        formatter: json  # 标准输出日志的格式
        formatter_config:
          time_fmt: 2006-01-02 15:04:05  # 日志时间格式。"2006-01-02 15:04:05"为常规时间格式，"seconds"为秒级时间戳，"milliseconds"为毫秒时间戳，"nanoseconds"为纳秒时间戳
          time_key: Time  # 日志时间字段名称，不填默认"T"，填 "none" 可禁用此字段
          level_key: Level  # 日志级别字段名称，不填默认"L"，填 "none" 可禁用此字段
          name_key: Name  # 日志名称字段名称，不填默认"N"，填 "none" 可禁用此字段
          caller_key: Caller  # 日志调用方字段名称，不填默认"C"，填 "none" 可禁用此字段
          message_key: Message  # 日志消息体字段名称，不填默认"M"，填 "none" 可禁用此字段
          stacktrace_key: StackTrace  # 日志堆栈字段名称，不填默认"S"，填 "none" 可禁用此字段
        writer_config:
          log_path: ./log/
          filename: keyless.log  # 本地文件滚动日志存放的路径
          write_mode: 1  # 日志写入模式，1-同步，2-异步，3-极速 (异步丢弃), 不配置默认异步模式
          roll_type: size  # 文件滚动类型，size 为按大小滚动
          max_age: 360  # 最大日志保留天数
          max_backups: 3  # 最大日志文件数
          compress: true  # 日志文件是否压缩
          max_size: 100  # 本地文件滚动日志的大小 单位 MB
```
3.项目配置(keyless.yaml)说明
```
private_key_path: /ssl # 用于业务认证(边缘节点认证)的证书目录，包括公钥和私钥
mutual_certs_path: /mutual_ssl # 跟转发节点双向认证的证书目录，包含公钥和私钥，根证书(可选)
prefer_server_cipher_suites: true # 以服务端证书算法为准(暂时没用)
log_path: /log # 日志路径
```
### 测试
#### 通过curl命令验证双向认证
使用curl命令直接测试,注意协议内容一定要符合json格式，不然无法正确通过

```
curl --resolve your.site.com:443:127.1.1.1 \
   https://your.site.com/KeylessRequest \
   -d '{ "Type": 2, "CertType": 47, "CertSn":  "your_cert_sn", "CertIssuer":  "your_cert_issuer", "Data":  "VGhpcyBpcyBhIHRlc3QgYmluYXJ5IGRhdGEu", "SignType": 3, "Padding": 3, "Seq": 123 }' \
   -H "Content-Type: application/json" -v \
   --cacert yourcacert.crt --cert yourcert.crt --key yourprivate.key
```
#### 测试动态更新边缘握手证书
* 公私钥更新都需要上传到./ssl目录下
* 本地调用热更新证书命令,这个是trpc.app.server.keylessHTTP服务，配置本地防止外网访问
```
curl -v http://127.0.0.1/KeylessReloadCerts
```
## 部署

必须包含以下几个文件,单独放到一个目录下即可
* keyless(可执行文件)
* log
* mutual_ssl
* ssl
* config
* trpc_go.yaml


## License

该项目根据MIT许可证获得许可 - 有关详细信息，请查看LICENSE.md文件。
