# HEU-PQC / LC01 PQC

本仓库包含 LC01 PQC 芯片的算法演示程序和双设备安全通信程序。两套程序位于独立目录，历史版本可执行文件分别保留。

## 最新发布：Secure Link v0

[lc01_secure_link](lc01_secure_link) 是面向“两台 Windows 电脑、各接一块 LC01、同一局域网”的独立原生程序。

- 双端临时签名公钥、挑战、KEM 公钥和密文相互绑定。
- A 在本机生成 KEM 密钥并解封装，B 在本机封装；网络不发送私钥、原始共享秘密或业务密钥。
- 双方经可信独立渠道核对完整 64 位十六进制会话指纹，并分别确认后，才开放文本和文件通信。
- HKDF-SHA-256 派生方向分离的 AES-256-GCM 密钥；完整报文头参与认证，严格检查会话、方向、序号和长度。
- 支持双向文本、图片或其他文件、分块传输、整文件 SHA-256、送达 ACK、重新建钥。
- 软件验证模式使用真实 OpenSSL ML-DSA-44/ML-KEM-512；硬件模式使用 LC01 固件命令。界面明确显示实际后端。
- C99 / Win32 / WinSock 原生程序，运行时不依赖 Python。

发布文件：[Windows v0 ZIP](LC01_Secure_Link_Windows_v0.zip) · [使用说明](lc01_secure_link/README.md) · [协议说明](lc01_secure_link/docs/protocol-v0.md) · [验证记录](lc01_secure_link/docs/verification-v0.md)

## 算法演示程序

[chip_dual_demo](chip_dual_demo) 包含双芯片 KEM、签名、篡改演示及文本/图片通信界面。v3.0、v3.1 和 v3.2 的源码与历史文档保留在仓库中；大型历史 EXE/ZIP 仅保留在本地发布目录。

## 更新日志

完整版本记录见 [read.md](read.md)。

## 安全边界

- 当前 Secure Link v0 使用项目自定义研究演示协议，不是 TLS、SPDM 或经过第三方审计的安全产品。
- 临时签名公钥本身不代表长期身份；本次会话的对端可信度来自双方经可信独立渠道核对会话指纹。无人值守的长期身份认证需要另行预置可信公钥或证书体系。
- 真实双板 LC01 互通、配置连续切换、现场吞吐和长时间稳定性仍需在目标硬件验收。
- MCU 移植、硬件加速和能耗数据尚未完成；QKD 与混合供钥尚未实现或验证。
