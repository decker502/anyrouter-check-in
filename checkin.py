#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

from dotenv import load_dotenv
from playwright.async_api import async_playwright

load_dotenv()

from notify import notify

BALANCE_HASH_FILE = 'balance_hash.txt'


def load_accounts():
	"""从环境变量加载多账号配置"""
	accounts_str = os.getenv('ANYROUTER_ACCOUNTS')
	if not accounts_str:
		print('ERROR: ANYROUTER_ACCOUNTS environment variable not found')
		return None

	try:
		accounts_data = json.loads(accounts_str)

		# 检查是否为数组格式
		if not isinstance(accounts_data, list):
			print('ERROR: Account configuration must use array format [{}]')
			return None

		# 验证账号数据格式
		for i, account in enumerate(accounts_data):
			if not isinstance(account, dict):
				print(f'ERROR: Account {i + 1} configuration format is incorrect')
				return None
			if 'cookies' not in account or 'api_user' not in account:
				print(f'ERROR: Account {i + 1} missing required fields (cookies, api_user)')
				return None
			# 如果有 name 字段，确保它不是空字符串
			if 'name' in account and not account['name']:
				print(f'ERROR: Account {i + 1} name field cannot be empty')
				return None

		return accounts_data
	except Exception as e:
		print(f'ERROR: Account configuration format is incorrect: {e}')
		return None


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	# 将包含 quota 和 used 的结构转换为简单的 quota 值用于 hash 计算
	simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def get_account_display_name(account_info, account_index):
	"""获取账号显示名称"""
	return account_info.get('name', account_info.get('api_user', f'Account {account_index + 1}'))


def mask_sensitive_info(text):
	"""屏蔽敏感信息，保留前2个字符，其余用*替代"""
	if not text or len(text) <= 2:
		return '***'
	return text[:2] + '*' * (len(text) - 2)


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


async def check_in_with_playwright(account_name: str, user_cookies: dict, api_user: str):
	"""使用 Playwright 执行完整的签到流程"""
	masked_name = mask_sensitive_info(account_name)
	print(f'[PROCESSING] {masked_name}: Starting browser for check-in...')

	async with async_playwright() as p:
		import tempfile
		with tempfile.TemporaryDirectory() as temp_dir:
			# 配置代理（如果设置了环境变量）
			proxy_config = None
			proxy_url = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
			if proxy_url:
				proxy_config = {'server': proxy_url}

			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=False,
				ignore_https_errors=True,
				proxy=proxy_config,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

			page = await context.new_page()

			try:
				# 步骤1：访问登录页面获取 WAF cookies
				print(f'[PROCESSING] {masked_name}: Accessing login page to get WAF cookies...')
				await page.goto('https://anyrouter.top/login', wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				# 步骤2：设置用户 cookies
				print(f'[PROCESSING] {masked_name}: Setting user cookies...')
				cookie_list = []
				for name, value in user_cookies.items():
					cookie_list.append({
						'name': name,
						'value': value,
						'domain': 'anyrouter.top',
						'path': '/',
					})
				await context.add_cookies(cookie_list)

				# 步骤3：访问控制台页面确保登录状态
				print(f'[PROCESSING] {masked_name}: Accessing console page...')
				await page.goto('https://anyrouter.top/console', wait_until='networkidle')
				await page.wait_for_timeout(2000)

				# 步骤4：使用浏览器的 fetch API 获取用户信息
				print(f'[PROCESSING] {masked_name}: Getting user info...')
				user_info_result = await page.evaluate(f"""
					async () => {{
						try {{
							const response = await fetch('https://anyrouter.top/api/user/self', {{
								method: 'GET',
								headers: {{
									'Accept': 'application/json, text/plain, */*',
									'new-api-user': '{api_user}'
								}},
								credentials: 'include'
							}});
							const text = await response.text();
							return {{ success: response.ok, status: response.status, text: text }};
						}} catch (error) {{
							return {{ success: false, error: error.toString() }};
						}}
					}}
				""")

				user_info = None
				if user_info_result.get('success'):
					try:
						data = json.loads(user_info_result['text'])
						if data.get('success'):
							user_data = data.get('data', {})
							quota = round(user_data.get('quota', 0) / 500000, 2)
							used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
							user_info = {
								'success': True,
								'quota': quota,
								'used_quota': used_quota,
								'display': f':money: Current balance: ${quota}, Used: ${used_quota}'
							}
							print(user_info['display'])
					except Exception as e:
						print(f'[WARN] {masked_name}: Failed to parse user info: {str(e)[:50]}')

				# 步骤5：使用浏览器的 fetch API 执行签到
				print(f'[NETWORK] {masked_name}: Executing check-in')
				checkin_result = await page.evaluate(f"""
					async () => {{
						try {{
							const response = await fetch('https://anyrouter.top/api/user/sign_in', {{
								method: 'POST',
								headers: {{
									'Accept': 'application/json, text/plain, */*',
									'Content-Type': 'application/json',
									'new-api-user': '{api_user}'
								}},
								credentials: 'include'
							}});
							const text = await response.text();
							return {{ success: response.ok, status: response.status, text: text }};
						}} catch (error) {{
							return {{ success: false, error: error.toString() }};
						}}
					}}
				""")

				print(f'[RESPONSE] {masked_name}: Response status code {checkin_result.get("status", "unknown")}')

				await context.close()

				# 处理签到结果
				if checkin_result.get('success'):
					try:
						result = json.loads(checkin_result['text'])
						if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
							print(f'[SUCCESS] {masked_name}: Check-in successful!')
							return True, user_info
						else:
							error_msg = result.get('msg', result.get('message', 'Unknown error'))
							print(f'[FAILED] {masked_name}: Check-in failed - {error_msg}')
							return False, user_info
					except json.JSONDecodeError:
						if 'success' in checkin_result['text'].lower():
							print(f'[SUCCESS] {masked_name}: Check-in successful!')
							return True, user_info
						else:
							print(f'[FAILED] {masked_name}: Check-in failed - Invalid response format')
							print(f'[DEBUG] Response: {checkin_result["text"][:200]}')
							return False, user_info
				else:
					error = checkin_result.get('error', 'Unknown error')
					print(f'[FAILED] {masked_name}: Check-in failed - {error}')
					return False, user_info

			except Exception as e:
				print(f'[FAILED] {masked_name}: Error during check-in: {str(e)[:100]}')
				await context.close()
				return False, None


async def check_in_account(account_info, account_index):
	"""为单个账号执行签到操作"""
	account_name = get_account_display_name(account_info, account_index)
	masked_name = mask_sensitive_info(account_name)
	print(f'\n[PROCESSING] Starting to process {masked_name}')

	# 解析账号配置
	cookies_data = account_info.get('cookies', {})
	api_user = account_info.get('api_user', '')

	if not api_user:
		print(f'[FAILED] {masked_name}: API user identifier not found')
		return False, None

	# 解析用户 cookies
	user_cookies = parse_cookies(cookies_data)
	if not user_cookies:
		print(f'[FAILED] {masked_name}: Invalid configuration format')
		return False, None

	# 使用 Playwright 执行完整的签到流程
	return await check_in_with_playwright(account_name, user_cookies, api_user)


async def main():
	"""主函数"""
	print('[SYSTEM] AnyRouter.top multi-account auto check-in script started (using Playwright)')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	# 加载账号配置
	accounts = load_accounts()
	if not accounts:
		print('[FAILED] Unable to load account configuration, program exits')
		sys.exit(1)

	print(f'[INFO] Found {len(accounts)} account configurations')

	# 加载余额hash
	last_balance_hash = load_balance_hash()

	# 为每个账号执行签到
	success_count = 0
	total_count = len(accounts)
	notification_content = []
	notified_accounts = set()  # 已添加到通知的账号 key
	current_balances = {}
	need_notify = False  # 是否需要发送通知
	balance_changed = False  # 余额是否有变化

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		try:
			success, user_info = await check_in_account(account, i)
			if success:
				success_count += 1

			# 检查是否需要通知
			should_notify_this_account = False

			# 如果签到失败，需要通知
			if not success:
				should_notify_this_account = True
				need_notify = True
				account_name = get_account_display_name(account, i)
				masked_name = mask_sensitive_info(account_name)
				print(f'[NOTIFY] {masked_name} failed, will send notification')

			# 收集余额数据
			if user_info and user_info.get('success'):
				current_quota = user_info['quota']
				current_used = user_info['used_quota']
				current_balances[account_key] = {'quota': current_quota, 'used': current_used}

			# 只有需要通知的账号才收集内容
			if should_notify_this_account:
				account_name = get_account_display_name(account, i)
				masked_name = mask_sensitive_info(account_name)
				status = '[SUCCESS]' if success else '[FAIL]'
				account_result = f'{status} {masked_name}'
				if user_info and user_info.get('success'):
					account_result += f'\n{user_info["display"]}'
				elif user_info:
					account_result += f'\n{user_info.get("error", "Unknown error")}'
				notification_content.append(account_result)
				notified_accounts.add(account_key)

		except Exception as e:
			account_name = get_account_display_name(account, i)
			masked_name = mask_sensitive_info(account_name)
			print(f'[FAILED] {masked_name} processing exception: {e}')
			need_notify = True  # 异常也需要通知
			notification_content.append(f'[FAIL] {masked_name} exception: {str(e)[:50]}...')
			notified_accounts.add(account_key)

	# 检查余额变化
	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			# 首次运行
			balance_changed = True
			need_notify = True
			print('[NOTIFY] First run detected, will send notification with current balances')
		elif current_balance_hash != last_balance_hash:
			# 余额有变化
			balance_changed = True
			need_notify = True
			print('[NOTIFY] Balance changes detected, will send notification')
		else:
			print('[INFO] No balance changes detected')

	# 为有余额变化的情况添加所有成功账号到通知内容
	if balance_changed:
		for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in current_balances:
				account_name = get_account_display_name(account, i)
				masked_name = mask_sensitive_info(account_name)
				# 只添加成功获取余额的账号，且避免重复添加
				if account_key not in notified_accounts:
					account_result = f'[BALANCE] {masked_name}'
					account_result += f'\n:money: Current balance: ${current_balances[account_key]["quota"]}, Used: ${current_balances[account_key]["used"]}'
					notification_content.append(account_result)

	# 保存当前余额hash
	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	if need_notify and notification_content:
		# 构建通知内容
		summary = [
			'[STATS] Check-in result statistics:',
			f'[SUCCESS] Success: {success_count}/{total_count}',
			f'[FAIL] Failed: {total_count - success_count}/{total_count}',
		]

		if success_count == total_count:
			summary.append('[SUCCESS] All accounts check-in successful!')
		elif success_count > 0:
			summary.append('[WARN] Some accounts check-in successful')
		else:
			summary.append('[ERROR] All accounts check-in failed')

		time_info = f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

		notify_content = '\n\n'.join([time_info, '\n'.join(notification_content), '\n'.join(summary)])

		print(notify_content)
		notify.push_message('AnyRouter Check-in Alert', notify_content, msg_type='text')
		print('[NOTIFY] Notification sent due to failures or balance changes')
	else:
		print('[INFO] All accounts successful and no balance changes detected, notification skipped')

	# 设置退出码
	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
