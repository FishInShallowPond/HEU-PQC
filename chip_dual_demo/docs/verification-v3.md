# v3 双向文本认证加密交付验证 — 2026-11-03

> 本文保留v3历史证据。v3.1的同窗口双模式及签名身份认证结果见[verification-v3.1.md](verification-v3.1.md)。

用户指定先实现原阶段2，再实施双电脑网络拆分。当前业务报文仅在一台电脑内存中转交。

## 自动验证

- `python -m unittest discover -s tests -v`：62/62通过，完整输出见[test-results-v3.txt](test-results-v3.txt)。保留原34项回归，新增28项密码记录层、KEM集成和真实Tk界面测试。
- 独立使用cryptography HKDF/AESGCM复算派生密钥和nonce，解开端点真实产生的记录；独立HMAC复算确认消息。验证方向分离、中文/emoji、空明文、65536B边界及超限不消耗nonce。
- 错误K、错误握手摘要、KEM公钥/密文篡改使密钥确认失败，禁止业务收发；不复制K1覆盖K2，不修改芯片输出。
- 密文、tag、头篡改，重复/跳号、跨会话、方向错误、截断和多余字节均拒绝；认证失败不交付明文。文本会话终止后不能继续使用旧业务密钥。
- 新建会话更新随机session_id/salt并重新派生，旧上下文关闭且历史保留；关闭文本窗口后重开继续原会话和计数；主会话断开使两端不可使用。
- 审查发现的并发关闭后发布新会话、重建与导出重复旧会话，均先由线程门控测试复现，再通过同一生命周期锁修复。异常加密库错误关闭两端、明确导出内部异常；已尝试交付的报文在解密内部异常时仍保留，且无接收明文。
- `python main.py --smoke-test`：实际Tk控件、后台队列和真实软件密码库，原有四条正常/篡改流程，以及KEM篡改后确认失败、双向中文、业务密文/tag/头篡改、重放、重建、导出、断开清理均通过。退出码0且stderr为空，见[gui-smoke-v3.log](gui-smoke-v3.log)。

## 界面与打包

- 实际创建并检查主窗口与1160×820文本窗口，150%桌面缩放下内容可读，报文区可滚动，发送/重建/导出按钮及状态可见。
- 主窗口：[preview_v3.png](preview_v3.png)；文本窗口：[preview_v3_text.png](preview_v3_text.png)。
- Windows x64单文件：`bin/LC01_DualChip_Demo_v3.exe`，保留原v2 EXE及专用`packaging_hooks/hook-workflow.py`。
- EXE从独立TEMP工作目录执行`--smoke-test`，确认完整扩展冒烟标记、退出码0及空stderr，运行记录与精确SHA256见[packaged-smoke-v3.txt](packaged-smoke-v3.txt)。构建日志见[build-v3.log](build-v3.log)。
- 当前验证环境：Windows、Python 3.13.9、cryptography 46.0.3、pyserial 3.5、PyInstaller 6.22.2。

## 证据边界

上述PQC供钥来自协议模拟器或测试串口替身，没有打开真实COM端口；真实双板仍需现场验收。HKDF/HMAC/AES-GCM使用真实密码实现，但模拟供钥不能证明PQC算法或硬件正确。本版未实现双电脑网络、设备身份认证、图片/音频、MCU或QKD。认证加密不等于可信设备身份，也不等于经过独立安全证明的通用传输协议。
