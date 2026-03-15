#!/bin/bash
# systemd timer 一键安装脚本
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Project dir: $PROJECT_DIR"

# 修改 service 中的路径
sed "s|/home/decker/app/tools/anyrouter-check-in/anyrouter-check-in|$PROJECT_DIR|g" "$SCRIPT_DIR/anyrouter-checkin.service" > /tmp/anyrouter-checkin.service

# 复制到用户 systemd 目录
mkdir -p ~/.config/systemd/user
cp /tmp/anyrouter-checkin.service ~/.config/systemd/user/anyrouter-checkin.service
cp "$SCRIPT_DIR/anyrouter-checkin.timer" ~/.config/systemd/user/

# 启用
systemctl --user daemon-reload
systemctl --user enable --now anyrouter-checkin.timer
loginctl enable-linger "$USER" 2>/dev/null || true

echo "Done. Run 'systemctl --user list-timers' to see next scheduled run."
