# 双芯片算法演示设计

v3.2新增聊天式文本/图片时间线、独立串口设置、芯片1本次会话签名/芯片2实际验签、文件分块认证加密、图片预览下载和本地密钥检查器，完整边界见[v3.2-design.md](v3.2-design.md)。v3.1及v3文本记录层的历史设计见[v3.1-design.md](v3.1-design.md)和[text-encryption-design.md](text-encryption-design.md)。下述为保留的算法演示芯片流程设计；双电脑网络拆分尚未实现。

目标：在 Windows Python/Tkinter 桌面界面，使用两路串口驱动两颗 LC01 芯片，完成密钥封装或数字签名演示。

采用独立目录，不修改既有测试工程。复用既有宏命令、算法配置及消息填充规则，独立实现严格的传输校验。方案选择桌面 Tkinter（无需浏览器、无需额外 GUI 包），而非浏览器服务或较重的 Qt。

- KEM：初始化两颗芯片 → 芯片1生成并读取公私钥 → 原样转发公钥给芯片2 → 芯片2封装并返回 CT、K2 → 原样转发 CT 给芯片1解封装 → 逐字节比较 K1/K2。
- 签名：初始化 → 芯片1生成并读取公私钥 → 芯片1签名 → 原样转发公钥、签名和同一消息给芯片2验签。私钥只在芯片1读取展示，不向芯片2写入。
- 每个字段显示正常顺序 uppercase HEX（整个串口字段逐字节反转），不改变芯片间转发数据。不补齐、不随机扩展、不改变返回结果。显示实际通信长度。
- 支持既有13个算法配置；KEM通信长度沿用既有800/1632/768/32 B配置，不将通信数据伪装为更长的标准参数集。签名消息1..1000 B且非8的倍数，沿用原7B填充规则；输入不符合时明确拒绝。
- 后台工作线程进行串口操作，GUI线程经事件队列更新；失败保留数据和日志并停止后续步骤。手动复位在开始运行前操作；独立芯片的签名/验签流程不插入人工重置。
- 支持分步、一键、停止（当前步骤结束后）、导出正常序HEX与实际TX/RX日志，打印至控制台。关闭释放两路串口。
- 默认真实硬件；另提供明确标注的流程模拟模式（哈希构造的协议替身，不是密码学实现，不能用于验证算法正确性），用于无硬件时检查界面与流程。

核心接口：`DemoConfig(algorithm='kyber512', port1='COM5', port2='COM6', baudrate=38580, timeout=0.2, command_timeout=20.0, command_interval=0.08, simulate=False, message=b'HEU dual chip demo')`；`DemoSession(config, emit=callable)`；`steps` 为当前流程的中文步骤名列表；`next_step` 为下个步骤索引；`step()` 执行一步，`run()` 执行剩余步骤，`stop()` 请求停止，`close()` 断开，`export(directory)` 导出。`fields` 为正常序bytes字典；`result` 为None/bool。

事件是字典：`{'type':'log','message':str}`、`{'type':'field','name':str,'data':bytes}`、`{'type':'step','index':int,'name':str,'state':'running'|'done'|'error'}`、`{'type':'result','ok':bool,'message':str}`。字段名：`pk`, `sk`, `ct`, `k1`, `k2`, `message`, `signature`, `verify_response`。

验证：用可记录的协议串口替身覆盖命令顺序、原样转发、数据字节序、坏帧/超时/部分读取、K不匹配和验签拒绝、失败资源清理、全部算法模拟流程；Tk窗口实际创建并执行模拟流程，检查布局与导出。真实硬件结果须现场接入两块芯片确认。

## 故障演示扩展

新增 `DemoConfig.pause_before_transfer=False`。启用后run在KEM公钥发送前(step2)、密文发送前(step4)，签名转发前(step3)暂停；发pause事件，waiting_for_transfer记录未执行步骤。再次run执行该步骤，下一发送点才再次暂停；step始终只执行下一步。

原始fields/raw不可由编辑操作覆盖。`pending_transfers`是正常序的只读映射（内部副本）；`editable_transfers`列出已生成但未发送的字段。`set_transfer(name, bytes)`等长编辑待发送副本，`reset_transfer(name)`恢复原始值。活动命令期间拒绝编辑；已发送字段不能重写。编辑事件为transfer，包含原始/副本/差异偏移。

新增正常序字段：received_pk（芯片2）、received_ct（芯片1，KEM）、received_signature/received_message（芯片2，签名）。只在相应命令获得有效响应后记录实际下发输入，明确不是芯片读回。KEM对比K1/K2、签名实际返回01仍是正常完成的失败结果，颜色差异不阻断。未知协议状态/超时等继续按通信错误处理。

默认比较原始/对端输入和K1/K2，按字节红色标注。编辑窗口以并排原始值和待发副本显示修改，可整段等长HEX编辑或按偏移/XOR翻转，支持恢复和继续。GUI发送前暂停可选择启用；普通模式保持原有行为。

导出包含完整原始/待发/实发数据、来源目标、差异偏移（正常序，从0开始）、编辑历史和交付/读回状态。结果仍记录芯片实际值；不能把篡改后的失败结果改成通过。
