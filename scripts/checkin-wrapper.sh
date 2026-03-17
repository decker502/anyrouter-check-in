#!/bin/bash
# 签到包装脚本：基于「今日是否已签到」决定是否执行，避免重复
# 可用于：cron 定时 + @reboot 开机补跑

cd "$(dirname "$0")/.." || exit 1
CHECK_FILE=".last_checkin_date"

today=$(date +%Y-%m-%d)
if [[ -f "$CHECK_FILE" ]] && [[ "$(cat "$CHECK_FILE")" == "$today" ]]; then
	echo "[SKIP] Already checked in today ($today)"
	exit 0
fi

echo "[RUN] Running check-in..."
if uv run checkin.py --provider agentrouter; then
	echo "$today" > "$CHECK_FILE"
	echo "[OK] Check-in done, saved date"
else
	echo "[FAIL] Check-in failed"
	exit 1
fi
