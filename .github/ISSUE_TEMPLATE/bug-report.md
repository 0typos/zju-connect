---
name: Bug Report
about: 报告 sangfordetunz 中存在的错误
title: ''
labels: bug
assignees: Mythologyli

---

**提交之前**

在提交报告之前，请确保：
+ 你正在使用 [Release](https://github.com/Mythologyli/zju-connect/releases) 中的最新版本
+ 如果你可以访问 CC98，请确保你已经阅读过以下说明：
    + [使用 ZJU Connect 代替 EasyConnect 提升你的 RVPN 体验](https://www.cc98.org/topic/5521873)
    + [端口转发、定时保活、自动选线、密码保存](https://www.cc98.org/topic/5570875)
+ 如果你是非 ZJU 用户，请先用最小配置确认问题仍然存在：在 `config.toml` 的 `[profiles.<名称>]` 中仅设置 `server_address`、`server_port`、`username`、`password`，并加上 `disable_server_config = true`、`skip_domain_resource = true`，然后 `sft check-config config.toml` 通过后由 `sftd` 启动、`sft up <名称>` 连接
+ 你已搜索过现有的 [Issues](https://github.com/Mythologyli/zju-connect/issues?q=is%3Aissue) 并且未发现重复

**确认无误后，请删除下方横线及以上内容。之后，请修改下方的模版并提交报告**

---

**软件版本**
v0.1.0 (Rust)

**Linux 使用环境**
发行版、内核版本、CPU 架构，以及是否使用 Docker

**服务端地址**
rvpn.zju.edu.cn:443

**服务端版本** (例如 `M7.6.8R2`。查看日志中的 `VPN server version`)


**故障描述** (建议结合图片说明)


**重现方法**


**预期行为**


**日志**
```
在此粘贴
```

**配置文件或启动参数** (请去除敏感信息)
```
在此粘贴
```
