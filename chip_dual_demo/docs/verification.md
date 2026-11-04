# v2故障演示交付验证 — 2026-11-03

本文保留为v2历史验证记录。v3新增双向文本认证加密的当前结果见[verification-v3.md](verification-v3.md)。

- `python -m unittest discover -s tests -v`：34/34通过；完整输出见 `test-results-v2.txt`，无Tk析构线程错误。
- `python main.py --smoke-test`：真实Tk控件和事件队列，正常KEM、正常签名、密文篡改、签名篡改共四条流程均通过；见 `gui-smoke-v2.log`。
- 全部13个算法配置及所有字段线长度与原 `HEU_py_acvp_pqc_main_v1/config.py` 比对一致。
- 两种流程经过真实SerialTransport代码与独立的分包模拟串口验证，通过。没有实际打开硬件COM端口。
- 实际GUI操作验证：分步接续、一键执行、发送前暂停、等长HEX编辑、XOR按偏移翻转、恢复、应用继续、只读历史、默认两侧字节差异标红、完整复制、导出和断开重建。
- 修改第0字节后，原始字段保持不变，实际串口命令包含被修改字节，对端输入显示修改后值；两个HEX控件只标红 `1.0..1.2`。KEM实际K不一致/验签合法01失败均保留False并执行到全部步骤完成。
- 默认1320×900及最小1120×780窗口检查：结果标签完整可见，字段和步骤可滚动；150% Windows缩放下预览保存在 `preview_tamper_editor.png`、`preview_tamper_kem.png`、`preview_tamper_signature.png`。
- v2独立核心审查提出“已发送但无有效响应时标为未发送”，已通过失败测试复现后修复，串口写入状态与有效响应确认分别导出；包括complete/partial/not_sent/unknown的回归验证。
- Windows x64单文件 `LC01_DualChip_Demo_v2.exe` 已打包；从独立TEMP工作目录运行正常/篡改四流程 `--smoke-test`，退出码0，见 `packaged-smoke-v2.txt`。
- EXE SHA256：`1C52CBF5CA9301776A494D52540CDD4B55AC15883DC91314F293D3109892F71E`。

硬件边界：以上不代表两颗真实芯片已通过互操作验证。需现场配置两路串口、复位两颗芯片并按README运行；所有硬件返回结果按实际值记录。流程模拟是协议替身，不实现密码算法。

