# mikrotik-api4smartdns

一个 smartdns 的插件，用于将 smartdns 的解析结果通过 mikrotik 的 api 写入 RouterBOARD 设备的 /ip/firewall/address-list。
其中 list 对应 smartdns 的 group 名称，timeout 对应 ttl（默认组不传）。

注意：我不懂 C++ 也不懂 Rust，纯 AI 编程（当前是 Deepseek-V4-Pro），发现 BUG 需要你自己修，增删功能也需要你自己改。

### 使用

编译：
```
cargo build  --release --target=rust的编译目标架构
```

smartdns 配置文件：
```
plugin 指向文件libmikrotik_api.so
mikrotik-api.address mikrotik的ip和端口号，例如192.168.1.96:8728
mikrotik-api.username 具有api，read，write权限的用户的用户名
mikrotik-api.password 上面用户对应的密码
mikrotik-api.ssl 是否使用api-ssl连接，填yes或no
```


