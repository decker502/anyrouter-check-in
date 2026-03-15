#!/usr/bin/env python3
"""
诊断脚本：在 CI 环境中运行，捕获 AgentRouter 请求的完整响应和运行环境信息，
用于对比本地成功 vs CI 失败时的真实差异。
"""

import asyncio
import json
import os
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

load_dotenv()

DIAGNOSTIC_FILE = 'diagnostic.json'


def get_runner_ip() -> str:
	"""获取本机公网 IP"""
	try:
		with httpx.Client(timeout=10) as client:
			r = client.get('https://api.ipify.org?format=json')
			return r.json().get('ip', 'unknown') if r.status_code == 200 else f'fetch_failed_{r.status_code}'
	except Exception as e:
		return f'error_{type(e).__name__}'


async def run_diagnostic():
	"""执行诊断：用真实账号配置访问 AgentRouter，捕获完整响应"""
	accounts_str = os.getenv('AGENTROUTER_ACCOUNTS')
	if not accounts_str:
		diag = {'error': 'AGENTROUTER_ACCOUNTS not set', 'runner_ip': get_runner_ip(), 'ci': bool(os.getenv('GITHUB_ACTIONS'))}
		with open(DIAGNOSTIC_FILE, 'w', encoding='utf-8') as f:
			json.dump(diag, f, ensure_ascii=False, indent=2)
		print('ERROR: AGENTROUTER_ACCOUNTS not set')
		sys.exit(1)

	try:
		accounts = json.loads(accounts_str)
		if not accounts or not isinstance(accounts, list):
			print('ERROR: AGENTROUTER_ACCOUNTS must be non-empty array')
			sys.exit(1)
		account = accounts[0]
		cookies = account.get('cookies', {})
		api_user = account.get('api_user', '')
		if isinstance(cookies, str):
			cookies = {c.strip().split('=', 1)[0]: c.strip().split('=', 1)[1] for c in cookies.split(';') if '=' in c}
	except Exception as e:
		diag = {'error': f'Parse AGENTROUTER_ACCOUNTS: {e}', 'runner_ip': get_runner_ip(), 'ci': bool(os.getenv('GITHUB_ACTIONS'))}
		with open(DIAGNOSTIC_FILE, 'w', encoding='utf-8') as f:
			json.dump(diag, f, ensure_ascii=False, indent=2)
		print(f'ERROR: Failed to parse AGENTROUTER_ACCOUNTS: {e}')
		sys.exit(1)

	site = 'agentrouter.org'
	runner_ip = get_runner_ip()
	print(f'[DIAG] Runner IP: {runner_ip}')
	print(f'[DIAG] In GitHub Actions: {bool(os.getenv("GITHUB_ACTIONS"))}')

	diag = {
		'timestamp': datetime.utcnow().isoformat() + 'Z',
		'ci': bool(os.getenv('GITHUB_ACTIONS')),
		'runner_ip': runner_ip,
		'site': site,
		'has_proxy': bool(os.getenv('HTTP_PROXY') or os.getenv('http_proxy')),
		'steps': [],
	}

	async with async_playwright() as p:
		import tempfile
		with tempfile.TemporaryDirectory() as temp_dir:
			proxy_url = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
			proxy_config = {'server': proxy_url} if proxy_url else None

			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=True,
				ignore_https_errors=True,
				proxy=proxy_config,
				args=['--disable-blink-features=AutomationControlled', '--no-sandbox'],
			)
			page = await context.new_page()

			try:
				# 步骤 1: 访问登录页
				print('[DIAG] Step 1: Goto login...')
				try:
					await page.goto(f'https://{site}/login', wait_until='networkidle', timeout=30000)
					diag['steps'].append({'name': 'goto_login', 'success': True})
				except Exception as e:
					diag['steps'].append({'name': 'goto_login', 'success': False, 'error': str(e)[:200]})
					print(f'[DIAG] goto_login FAILED: {e}')
					with open(DIAGNOSTIC_FILE, 'w', encoding='utf-8') as f:
						json.dump(diag, f, ensure_ascii=False, indent=2)
					print(f'[DIAG] Written to {DIAGNOSTIC_FILE}')
					sys.exit(1)

				await page.wait_for_timeout(2000)

				# 步骤 2: 设置 cookies
				cookie_list = [{'name': k, 'value': str(v), 'domain': site, 'path': '/'} for k, v in cookies.items()]
				await context.add_cookies(cookie_list)
				diag['steps'].append({'name': 'add_cookies', 'success': True})

				# 步骤 3: 访问 console
				print('[DIAG] Step 2: Goto console...')
				try:
					await page.goto(f'https://{site}/console', wait_until='networkidle', timeout=30000)
					diag['steps'].append({'name': 'goto_console', 'success': True})
				except Exception as e:
					diag['steps'].append({'name': 'goto_console', 'success': False, 'error': str(e)[:200]})
					print(f'[DIAG] goto_console FAILED: {e}')

				await page.wait_for_timeout(2000)

				# 步骤 4: Fetch /api/user/self
				print('[DIAG] Step 3: Fetch /api/user/self...')
				result = await page.evaluate(f"""
					async () => {{
						try {{
							const r = await fetch('https://{site}/api/user/self', {{
								method: 'GET',
								headers: {{ 'Accept': 'application/json', 'new-api-user': '{api_user}' }},
								credentials: 'include'
							}});
							const text = await r.text();
							const headers = {{}};
							r.headers.forEach((v, k) => headers[k] = v);
							return {{ ok: r.ok, status: r.status, statusText: r.statusText, headers, text }};
						}} catch (e) {{
							return {{ error: e.toString() }};
						}}
					}}
				""")

				await context.close()

				if 'error' in result:
					diag['api_response'] = {'error': result['error']}
				else:
					diag['api_response'] = {
						'ok': result.get('ok'),
						'status': result.get('status'),
						'statusText': result.get('statusText'),
						'headers': {k: v for k, v in (result.get('headers') or {}).items() if k.lower() in ('content-type', 'content-length')},
						'text_length': len(result.get('text', '')),
						'text_preview': (result.get('text', '')[:2000] + '...[truncated]') if len(result.get('text', '')) > 2000 else result.get('text', ''),
						'text_start': (result.get('text', '') or '')[:100],
					}

			except Exception as e:
				diag['exception'] = str(e)[:500]
				await context.close()

	with open(DIAGNOSTIC_FILE, 'w', encoding='utf-8') as f:
		json.dump(diag, f, ensure_ascii=False, indent=2)

	print(f'[DIAG] Written to {DIAGNOSTIC_FILE}')
	print(f'[DIAG] API status: {diag.get("api_response", {}).get("status", "N/A")}')
	print(f'[DIAG] Response preview: {str(diag.get("api_response", {}).get("text_start", ""))[:80]!r}')


if __name__ == '__main__':
	asyncio.run(run_diagnostic())
