# AgentRouter 签到调试

## systemd timer 无界面运行

签到脚本会**自动检测**无界面环境（`DISPLAY` 未设置或 `HEADLESS=1`），使用 headless 模式，无需 X11。service 中已设置 `Environment=HEADLESS=1`。

本地模拟测试：`HEADLESS=1 uv run checkin.py --provider agentrouter --index 1`

---

## 卡在 GitHub 页面时如何调试

使用 `--debug` 运行，会：

1. 每 5 轮打印一次 GitHub 页面诊断：
   - 当前 URL、匹配的 `name`/`github_login` 提示
   - `.Box .Box-row` 行数及每行的 `hasContinue`/`hasSelect` 状态
2. 保存 `debug_github.png` 截图（覆盖写入）
3. 打印 `_try_github_continue` 的返回值

```bash
uv run checkin.py --provider agentrouter --index 1 --debug
```

根据输出判断：

- 若 `rowCount=0`：页面结构可能变化，选择器不匹配
- 若 `hasContinue`/`hasSelect` 全为 false：表单选择器需调整
- 若 `_try_github_continue => {ok: false}`：JS 未找到可点击目标，检查 `debug_github.png` 对应页面

---

## 网络请求参考

anyrouter 登录后触发的请求：
- github?code=...&state=...  200
- status / models / groups / token  200
- sign_in
