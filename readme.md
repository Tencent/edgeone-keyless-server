English | [中文](readme.zh_CN.md)
# Edgeone Keyless Server

A service developed based on the trpc-go framework that supports the independent deployment of private keys during the SSL handshake authentication process, ensuring higher security for private keys. It also supports the following features:
```
1. Supports mutual authentication (mutual authentication with handshake nodes)
2. Supports multiple certificate types for mutual authentication (RSA, ECC)
3. Supports hot loading of public and private key certificates (as public and private key certificates for establishing SSL handshake nodes)
4. Supports remote authentication certificate types (RSA)
5. Supports simple configuration management services, such as certificates, IPs, ports, logs, etc.
6. Supports viewing current actual access performance parameters (QPS, counts, average response time, etc.)
```

## Quick Start

### Prerequisites

- **[Go](https://go.dev/doc/install)**, version should be greater than or equal to go1.20.
- **[tRPC cmdline tools](https://github.com/trpc-group/trpc-cmdline)**, used for generating PB (protobuf) protocol code.
- **[trpc-go](https://github.com/trpc-group/trpc-go)**, version v1.0.3.
- **[OpenSSL](https://github.com/openssl/openssl?tab=readme-ov-file#build-and-install)**, requires related libraries `openssl-static`, `openssl-devel`, and `zlib-devel`.
    ```bash
    # On CentOS:
    sudo yum install openssl-static -y
    sudo yum install openssl-devel -y
    sudo yum install zlib-devel -y
    ```
    ```
    # On Debian-based Linux:
    sudo apt-get install openssl-static
    sudo apt-get install openssl-devel 
    sudo apt-get install zlib-devel
    ```

### Installation

You can run the server by compiling the source code. An RPM package will be provided later for direct installation.

## Get the Source Code
```
git clone https://github.com/tencent/edgeone-keyless-server.git
cd edgeone-keyless-server
```
### Directory Structure
```
edgeone-keyless-server
├── application
├── config              // Configuration file directory
│   └── keyless.yaml    // Configuration file
├── domain              // Domain layer
│   ├── entity          // Entity layer
│   │   ├── cipher_suites.go    // Key suites
│   │   ├── common.go
│   │   ├── config.go
│   │   ├── ecc.go
│   │   ├── load_cert_info.go   // Load certificate information
│   │   ├── metric.go           // QPS and other metrics statistics
│   │   ├── rsa.go              // RSA algorithm
│   │   └── rwlock.go           // Read-write lock
│   ├── repository              // Data access layer
│   │   ├── key_agreement.go    // Define data encryption, decryption, signature, etc.
│   │   └── keyless.go          // Define data access layer
│   └── service                 // Service layer
│       ├── keyless.go          // Define service layer (define request certificate encryption, decryption, signature; reload certificate and other services;)
│       └── load_cert.go        // Load certificate
├── go.mod
├── go.sum
├── infrastructure              // Infrastructure layer
│   ├── config
│   ├── constant                // Constants
│   │   ├── const.go
│   │   ├── error.go            // Error information
│   │   └── response.go         // Error codes
│   ├── db
│   ├── log
│   ├── middleware
│   ├── protocol                // Protocol layer
│   │   ├── keyless             // Define protocol layer
│   │   │   ├── keyless_server.pb.go
│   │   │   ├── keyless_server.trpc.go
│   │   │   └── mock
│   │   │       └── keyless_server_mock.go
│   │   └── pb
│   │       ├── keyless.go            // Generate protocol
│   │       └── keyless_server.proto  // Define protocol layer
│   └── utils                    // Utility layer
│       ├── system.go            // System common functions
│       ├── system_test.go
│       ├── time.go              // Time common functions
│       └── time_test.go
├── log             // Log directory
├── main.go         // Server entry
├── mutual_ssl      // Mutual authentication certificate directory
├── presentation
│   └── api
├── readme.md
├── readme.zh_CN.md
├── ssl             // SSL certificate directory
├── testdata
└── trpc_go.yaml    // trpc-go configuration
```

### Execution Example

1. Compile and run the server code; related configurations have been completed in `trpc_go.yaml`.
```
go build -o keyless main.go
chmod a+x keyless
./keyless
```

2. Explanation of `trpc_go.yaml` configuration:
```
server:  # Server configuration
  service:  # Specific business service configuration
    - name: trpc.app.server.keylessHTTP # Local access (optional), convenient for locally reloading edge authentication certificates (non-mutual authentication certificates)
      protocol: http  # Application layer protocol trpc http
      ip: 127.0.0.1
      port: 8080
    - name: trpc.app.server.keylessHTTPSMutual
      timeout: 10000  # Unit ms, each received request is allowed a maximum execution time of 1000ms, so be careful to balance the timeout allocation for all serial RPC calls within the current request, default is 0, no timeout set
      protocol: http  # Application layer protocol trpc http
      ip: x.x.x.x  # Bind the external service IP
      port: 443  # Default SSL port
      tls_cert: "/your_keyless_path/mutual_ssl/yourcert.crt"  # Public key
      tls_key: "/your_keyless_path/mutual_ssl/yourprivatecert.key"  # Private key
      ca_cert: "/your_keyless_path/mutual_ssl/yourca.pem"  # CA certificate, must be configured if mutual authentication is required
plugins:
  log:  # All log configurations
    default:  # Default log configuration, log.Debug("xxx")
      - writer: console  # Console standard output default
        level: debug  # Standard output log level
    custom:  # Default log configuration, log.Debug("xxx")
      - writer: console  # Console standard output default
        level: debug  # Standard output log level
      - writer: file  # Local file log
        level: debug  # Local file rolling log level
        formatter: json  # Standard output log format
        formatter_config:
          time_fmt: 2006-01-02 15:04:05  # Log time format. "2006-01-02 15:04:05" is the conventional time format, "seconds" is second-level timestamp, "milliseconds" is millisecond-level timestamp, "nanoseconds" is nanosecond-level timestamp
          time_key: Time  # Log time field name, not filled defaults to "T", fill "none" to disable this field
          level_key: Level  # Log level field name, not filled defaults to "L", fill "none" to disable this field
          name_key: Name  # Log name field name, not filled defaults to "N", fill "none" to disable this field
          caller_key: Caller  # Log caller field name, not filled defaults to "C", fill "none" to disable this field
          message_key: Message  # Log message body field name, not filled defaults to "M", fill "none" to disable this field
          stacktrace_key: StackTrace  # Log stack trace field name, not filled defaults to "S", fill "none" to disable this field
        writer_config:
          log_path: ./log/
          filename: keyless.log  # Local file rolling log storage path
          write_mode: 1  # Log writing mode, 1-synchronous, 2-asynchronous, 3-ultra-fast (asynchronous discard), defaults to asynchronous mode
          roll_type: size  # File rolling type, size for rolling by size
          max_age: 360  # Maximum log retention days
          max_backups: 3  # Maximum number of log files
          compress: true  # Whether to compress log files
          max_size: 100  # Local file rolling log size in MB
```

3. Explanation of project configuration (`keyless.yaml`):
```
private_key_path: /ssl # Directory for business authentication (edge node authentication) certificates, including public and private keys
mutual_certs_path: /mutual_ssl # Directory for certificates for mutual authentication with forwarding nodes, including public and private keys, root certificate (optional)
prefer_server_cipher_suites: true # Based on server certificate algorithm (currently not used)
log_path: /log # Log path
```

### Testing
#### Verify Mutual Authentication Using curl Command
Use the `curl` command to test directly. Note that the protocol content must conform to JSON format; otherwise, it cannot be processed correctly.

```
curl --resolve your.site.com:443:127.1.1.1 \
   https://your.site.com/KeylessRequest \
   -d '{ "Type": 1, "CertType": 11, "CertSn":  "your_cert_sn", "CertIssuer":  "your_cert_issuer", "Data":  "base64", "SignType": 1, "Padding": 1, "Seq": 123 }' \
   -H "Content-Type: application/json" -v \
   --cacert yourcacert.crt --cert yourcert.crt --key yourprivate.key
```
#### Test Dynamic Update of Edge Handshake Certificate
* Both public and private key updates need to be uploaded to the ./ssl directory.
* Call the local hot update certificate command locally, this is the trpc.app.server.keylessHTTP service, configured locally to prevent external network access.
```
curl -v http://127.0.0.1/KeylessReloadCerts
```
## Deployment

The following files must be included and placed in a separate directory:
* keyless (executable file)
* log
* mutual_ssl
* ssl
* config
* trpc_go.yaml

## License

This project is licensed under the MIT License - for more details, please see the LICENSE file.

## Contribution
If you have any ideas or suggestions to improve Edgeone Keyless Server, welcome to submit an issue/pull request.