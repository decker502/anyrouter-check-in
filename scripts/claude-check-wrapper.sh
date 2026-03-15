#!/bin/bash
# AgentRouter Claude 模型检查包装脚本
cd "$(dirname "$0")/.." || exit 0
uv run check_claude_models.py
