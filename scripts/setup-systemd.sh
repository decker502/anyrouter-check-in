#!/bin/bash
# systemd timer 一键安装脚本（签到 + Claude 模型检查）
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Project dir: $PROJECT_DIR"

# 修改 service 中的路径
sed "s|/home/decker/app/tools/anyrouter-check-in/anyrouter-check-in|$PROJECT_DIR|g" "$SCRIPT_DIR/anyrouter-checkin.service" > /tmp/anyrouter-checkin.service
sed "s|/home/decker/app/tools/anyrouter-check-in/anyrouter-check-in|$PROJECT_DIR|g" "$SCRIPT_DIR/agentrouter-claude-check.service" > /tmp/agentrouter-claude-check.service

# 复制到用户 systemd 目录
mkdir -p ~/.config/systemd/user
cp /tmp/anyrouter-checkin.service ~/.config/systemd/user/anyrouter-checkin.service
cp "$SCRIPT_DIR/anyrouter-checkin.timer" ~/.config/systemd/user/
cp /tmp/agentrouter-claude-check.service ~/.config/systemd/user/agentrouter-claude-check.service
cp "$SCRIPT_DIR/agentrouter-claude-check.timer" ~/.config/systemd/user/

# 启用
systemctl --user daemon-reload
systemctl --user enable --now anyrouter-checkin.timer
systemctl --user enable --now agentrouter-claude-check.timer
loginctl enable-linger "$USER" 2>/dev/null || true

echo "Done. Run 'systemctl --user list-timers' to see next scheduled run."
