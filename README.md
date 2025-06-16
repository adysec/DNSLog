# DNSLog Dashboard

## 项目简介

DNSLog Dashboard 是一个基于 Rust 的 DNS 日志记录平台，集成了 DNS 服务和 Web 仪表盘，主要用于捕获和记录 DNS 查询日志。该项目支持自动注册用户、生成唯一子域名以及实时展示 DNS 日志，适用于安全测试、信息外传及漏洞验证等场景。

## 环境依赖

- **Rust 环境：** 推荐使用最新稳定版 Rust 和 Cargo。
- **SQLite 数据库：** 程序会在运行目录下自动生成 `dnslog.db` 数据库文件。
- 主要依赖库：
  - [actix-web](https://github.com/actix/actix-web)
  - [trust-dns-server](https://github.com/bluejekyll/trust-dns)
  - [rusqlite](https://github.com/rusqlite/rusqlite)
  - [r2d2](https://github.com/sorenvurgh/r2d2) 及 [r2d2-sqlite](https://github.com/ivanceras/r2d2-sqlite)
  - [tokio](https://github.com/tokio-rs/tokio)
  - [async_trait](https://github.com/dtolnay/async-trait)
  - [chrono](https://github.com/chronotope/chrono)
  - [rand](https://github.com/rust-random/rand)
  - [serde](https://github.com/serde-rs/serde)

## DNS 配置方法

1. **配置A记录允许通过域名访问web页面：**
```bash
#名称 类型 内容
dnslog  A  xxx.xxx.xxx.xxx
```
![图片](https://github.com/user-attachments/assets/f435df2e-3722-45b5-8ed3-0c54f4f61d3e)


2. **配置ns服务器：**
```bash
#名称 类型 内容
ns1  A  xxx.xxx.xxx.xxx
ns2  A  xxx.xxx.xxx.xxx
dns  ns  ns1.xxx.com
dns  ns  ns2.xxx.com
```
![图片](https://github.com/user-attachments/assets/04b65e6e-c3a5-454a-932a-684511536f41)
![图片](https://github.com/user-attachments/assets/3e2d1f5f-dcbc-4a5f-b255-eb9b43aa447e)


## 安装与构建

1. **克隆代码：**
```bash
git clone https://github.com/adysec/dnslog-rs
```

2. **构建项目：**

```bash
cargo build --release
```

3. **运行程序：**

```bash
./dnslog-rs
```
