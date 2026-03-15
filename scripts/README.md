# 本机定时签到

实现「到点执行 + 错过则开机补跑」：每天 6:00 执行，若当时未开机，开机后自动补跑。

## 方案 A：systemd timer（推荐，Linux）

### 一键安装

```bash
cd /path/to/anyrouter-check-in  # 进入项目目录
./scripts/setup-systemd.sh
```

会同时安装：
- **签到定时器**：每天 6:00，错过则开机补跑
- **Claude 模型检查**：每 30 分钟检查 AgentRouter 模型列表，若有 Claude 相关模型则发钉钉提醒（需配置 `AGENTROUTER_ACCOUNTS` 与 `DINGDING_WEBHOOK`）

### 手动安装

```bash
# 1. 修改 service 中的路径
sed -i "s|/home/decker/app/tools/anyrouter-check-in/anyrouter-check-in|$(pwd)|g" scripts/anyrouter-checkin.service
sed -i "s|/home/decker/app/tools/anyrouter-check-in/anyrouter-check-in|$(pwd)|g" scripts/agentrouter-claude-check.service

# 2. 复制到用户 systemd 目录
mkdir -p ~/.config/systemd/user
cp scripts/anyrouter-checkin.service scripts/anyrouter-checkin.timer ~/.config/systemd/user/
cp scripts/agentrouter-claude-check.service scripts/agentrouter-claude-check.timer ~/.config/systemd/user/

# 3. 启用并启动
systemctl --user daemon-reload
systemctl --user enable --now anyrouter-checkin.timer
systemctl --user enable --now agentrouter-claude-check.timer

# 4. 启用 linger（未登录时也能执行）
loginctl enable-linger $USER

# 5. 查看状态
systemctl --user list-timers
```

### 常用命令

| 命令 | 说明 |
|------|------|
| `systemctl --user list-timers` | 查看下次执行时间 |
| `systemctl --user start anyrouter-checkin.service` | 立即执行签到 |
| `systemctl --user start agentrouter-claude-check.service` | 立即执行 Claude 模型检查 |
| `systemctl --user stop anyrouter-checkin.timer` | 停止签到定时 |
| `systemctl --user stop agentrouter-claude-check.timer` | 停止 Claude 模型检查定时 |
| `systemctl --user disable anyrouter-checkin.timer` | 禁用签到定时 |
| `systemctl --user disable agentrouter-claude-check.timer` | 禁用 Claude 模型检查定时 |

## 方案 B：Cron + 开机补跑

```bash
chmod +x scripts/checkin-wrapper.sh scripts/claude-check-wrapper.sh
crontab -e

# 添加：
# 每天 6:00 签到
0 6 * * * /绝对路径/anyrouter-check-in/scripts/checkin-wrapper.sh
# 开机 5 分钟后补跑签到
@reboot sleep 300 && /绝对路径/anyrouter-check-in/scripts/checkin-wrapper.sh

# （可选）每 30 分钟检查 AgentRouter Claude 模型
*/30 * * * * /绝对路径/anyrouter-check-in/scripts/claude-check-wrapper.sh
```

## Windows 任务计划

1. 任务计划程序 → 创建基本任务
2. 触发器：每日 6:00，以及「启动时」
3. 操作：运行程序，填 `uv`，参数 `run checkin.py`，起始于项目目录
4. 设置 → 勾选「如果错过计划开始时间，尽快运行任务」

## 防重复逻辑

- **签到**：`checkin-wrapper.sh` 使用 `.last_checkin_date` 记录当日是否已执行，同一天内不重复跑
- **Claude 模型检查**：`check_claude_models.py` 使用 `.last_claude_notify_date` 记录当日是否已发送钉钉提醒，同一天内不重复通知
