#!/usr/bin/env python3
"""
AgentRouter 模型列表检查：若发现 Claude 相关模型则通过钉钉通知
用于定时监控 AgentRouter 是否已上架 Claude 模型
使用 /api/user/models 接口（与页面一致），需 AGENTROUTER_ACCOUNTS 认证
"""

import json
import os
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv

load_dotenv()

try:
	from notify import notify
except ImportError:
	notify = None


def _load_agentrouter_account():
	"""加载第一个 AgentRouter 账号，返回 (session, api_user) 或 None"""
	accounts_str = os.getenv('AGENTROUTER_ACCOUNTS')
	if not accounts_str:
		return None
	try:
		accounts = json.loads(accounts_str)
		if not accounts or not isinstance(accounts, list):
			return None
		acc = accounts[0]
		cookies = acc.get('cookies', {})
		if isinstance(cookies, str):
			cookies = {c.strip().split('=', 1)[0]: c.strip().split('=', 1)[1] for c in cookies.split(';') if '=' in c}
		session = cookies.get('session') if isinstance(cookies, dict) else None
		api_user = acc.get('api_user', '')
		if session and api_user:
			return session, api_user
	except Exception:
		pass
	return None


def get_agentrouter_models() -> list[str] | None:
	"""从 AgentRouter /api/user/models 获取模型列表，返回 model id 列表，失败返回 None"""
	account = _load_agentrouter_account()
	if not account:
		print('[WARN] AGENTROUTER_ACCOUNTS 未配置或格式有误，跳过检查')
		return None

	session, api_user = account
	url = 'https://agentrouter.org/api/user/models'
	proxy_url = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
	proxy = proxy_url if proxy_url else None

	try:
		with httpx.Client(timeout=30.0, proxy=proxy) as client:
			resp = client.get(
				url,
				headers={
					'Accept': 'application/json, text/plain, */*',
					'new-api-user': api_user,
				},
				cookies={'session': session},
			)
			resp.raise_for_status()
			data = resp.json()
	except Exception as e:
		print(f'[ERROR] 获取模型列表失败: {e}')
		return None

	if not data.get('success'):
		print('[WARN] API 返回 success=false')
		return None

	models = data.get('data')
	if not models or not isinstance(models, list):
		print('[WARN] 响应格式异常，无法解析模型列表')
		return None

	return [str(m) if isinstance(m, str) else str(m.get('id', m)) for m in models]


def has_claude_models(model_ids: list[str]) -> list[str]:
	"""检查模型列表中是否包含 Claude 相关模型，返回匹配的 id 列表"""
	claude_models = []
	for mid in model_ids:
		if 'claude' in mid.lower():
			claude_models.append(mid)
	return claude_models


def should_skip_notify() -> bool:
	"""今日已发送过 Claude 提醒则跳过，避免重复轰炸"""
	flag_file = '.last_claude_notify_date'
	today = datetime.now().strftime('%Y-%m-%d')
	try:
		if os.path.exists(flag_file):
			with open(flag_file, 'r', encoding='utf-8') as f:
				return f.read().strip() == today
	except Exception:
		pass
	return False


def mark_notified():
	"""记录今日已发送通知"""
	flag_file = '.last_claude_notify_date'
	today = datetime.now().strftime('%Y-%m-%d')
	try:
		with open(flag_file, 'w', encoding='utf-8') as f:
			f.write(today)
	except Exception as e:
		print(f'[WARN] 无法写入 {flag_file}: {e}')


def main():
	print(f'[TIME] {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} - AgentRouter Claude 模型检查')

	model_ids = get_agentrouter_models()
	if model_ids is None:
		sys.exit(0)  # 未配置或失败，静默退出

	claude_models = has_claude_models(model_ids)
	if not claude_models:
		print('[INFO] 当前无 Claude 相关模型，不发送通知')
		sys.exit(0)

	# 今日已发过提醒则跳过，避免每 30 分钟重复轰炸
	if should_skip_notify():
		print('[INFO] 今日已发送过 Claude 提醒，跳过')
		sys.exit(0)

	# 发现 Claude 模型，发送钉钉通知
	title = 'AgentRouter Claude 模型提醒'
	content = (
		f'[TIME] {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n'
		f'AgentRouter 模型列表中已包含 Claude 相关模型：\n'
		f'{chr(10).join("- " + m for m in claude_models)}\n\n'
		f'可在 https://agentrouter.org/console 查看'
	)
	print(f'[NOTIFY] 发现 Claude 模型: {claude_models}')
	print(content)

	if notify and notify.dingding_webhook:
		try:
			notify.send_dingtalk(title, content)
			mark_notified()
			print('[OK] 钉钉通知已发送')
		except Exception as e:
			print(f'[ERROR] 发送钉钉通知失败: {e}')
			sys.exit(1)
	else:
		print('[WARN] DINGDING_WEBHOOK 未配置，无法发送钉钉通知')

	sys.exit(0)


if __name__ == '__main__':
	main()
