# v3 历史设计：本机双向文本认证加密

> v3.1已在此记录层之前增加显式可信身份及签名绑定KEM，并改为同窗口双模式。当前身份/握手边界以[v3.1-design.md](v3.1-design.md)为准；本文保留v3记录层设计。

用户已指定先实施原阶段2，双电脑网络拆分后置。保留原测试目录及v2 EXE，修改迁移副本。

## 边界

现有双串口KEM完成后，A仅由K1派生本地密钥，B仅由K2派生本地密钥。业务报文在电脑内存中转交，不经过串口或TCP。两端HKDF和AES-GCM使用真实cryptography实现；模拟模式的K来自协议替身，不能据此验证PQC算法或硬件。没有设备身份认证。

## 会话与记录

- 每次新建文本会话独立产生16B随机session_id及32B随机HKDF salt。应用不持久化业务密钥和计数器，重启/断开必须新建会话。新建会话可复用当前KEM的K，但派生上下文、salt及session_id全部更新；不复用旧业务密钥。
- 两端分别对自身掌握的算法ID、正常序PK、正常序CT进行无歧义长度编码并作SHA-256摘要。A使用原PK与实际收到的CT，B使用实际收到的PK与原CT。
- HKDF-SHA-256 info绑定版本、会话、握手摘要、方向和用途。分别派生A→B/B→A的32B AES密钥、4B nonce前缀及32B确认密钥。
- 双向HMAC-SHA-256确认绑定方向和完整会话上下文。两端均验证成功后才能发送文本。确认通过不等于设备身份可信。
- 记录头为网络序struct `!4sBBB16sQI`：magic=LC3T、version=1、type=1、direction=0或1、session_id、uint64序号、uint32密文含tag长度。整个头作为AAD。
- nonce为方向派生的4B前缀加8B序号。每方向从0开始；最多2^20条记录、64MiB明文字节，每条UTF-8最多65536B。达到限额后要求新建会话。
- 收端严格顺序接收，拒绝重复/跳号/跨会话/错误方向/非法头/长度异常。认证或协议错误终止整个文本会话，后续必须显式新建会话。失败不交付明文。
- GUI支持A→B、B→A，密文/tag/报文头篡改及重放。保留原始密文与实际交付报文、确认结果、成功/拒绝原因、成功接收明文。派生秘密不显示、不导出。原v2导出仍包含本地原始SK/K。
- 关闭文本窗口保留会话和审计记录，重新打开继续原计数；“新建文本会话”销毁旧端点并保留其导出快照；主会话断开立即关闭所有文本密钥上下文。Python不承诺内存安全擦除。

## 代码边界与接口

- `text_crypto.py`: `transcript_hash(algorithm, pk, ct) -> bytes`; `SecureEndpoint(role, secret, session_id, salt, transcript)`；`confirmation()`, `verify_confirmation(token)`, `encrypt(plaintext: bytes) -> bytes`, `decrypt(packet: bytes) -> bytes`, `close()`；`TextExchange(key_a, key_b, transcript_a, transcript_b, simulate=False)`；属性`ready`, `session_id`, `history`；`send(sender: 'A'|'B', text: str, fault='none') -> dict`, `replay_last() -> dict`, `export_data() -> dict`, `close()`。
- `workflow.py`: `DemoSession.open_text_exchange(reset=False)`负责验证生命周期并把各自K及各自握手记录交给TextExchange；`text_exchange`当前会话；`text_exchanges`过往快照；export增加`text_sessions.json`，close使当前端点不可使用。
- `text_window.py`: 双向输入和接收历史、真实密文/tag/nonce/头HEX、故障选项、新建会话、记录导出；主GUI通过“文本加密通信”入口打开，仅完整KEM流程可用。签名流程禁用。

## 验收

真实HKDF/AES独立复算互通；中文、空消息、边界长度；双向密钥分离；递增nonce；错误K/握手上下文确认失败；密文/tag/AAD篡改不交付明文；重放/乱序/跨会话拒绝；超限拒绝且不回绕；重建与断开生命周期；原34测试继续通过；实际Tk测试、源码及v3独立目录EXE冒烟。硬件结果仍需现场验证。

参考：https://cryptography.io/en/stable/hazmat/primitives/aead/ ，https://www.rfc-editor.org/rfc/rfc5869.html 。此为演示协议，不是TLS或经过独立安全证明的通用协议。
