#!/usr/bin/env python3
"""
AnyRouter Session 刷新工具

本地辅助脚本，用于半自动刷新 anyrouter 的 session cookie。
使用持久化浏览器配置，首次运行需完整登录 GitHub，
后续运行 GitHub 登录状态自动保留，只需点击「Login with GitHub」即可。

使用方法：
    uv run refresh_session.py
"""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv
from playwright.async_api import async_playwright

load_dotenv()

BROWSER_PROFILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.browser_profile')
ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')

SITE_CONFIGS = [
	('ANYROUTER_ACCOUNTS', 'anyrouter.top'),
	('AGENTROUTER_ACCOUNTS', 'agentrouter.org'),
]


def load_existing_accounts(env_var: str = 'ANYROUTER_ACCOUNTS') -> list | None:
	"""从 .env 文件读取现有账号配置"""
	accounts_str = os.getenv(env_var)
	if not accounts_str:
		return None
	try:
		accounts = json.loads(accounts_str)
		if isinstance(accounts, list):
			return accounts
	except json.JSONDecodeError:
		pass
	return None


def get_account_display_name(account: dict, index: int) -> str:
	"""获取账号显示名称"""
	return account.get('name', account.get('api_user', f'Account {index + 1}'))


async def clear_site_cookies(context, site: str = 'anyrouter.top'):
	"""清除指定站点的 cookies，保留其他网站（如 GitHub）的登录状态"""
	try:
		await context.clear_cookies(domain=site)
	except TypeError:
		all_cookies = await context.cookies()
		await context.clear_cookies()
		keep = [c for c in all_cookies if site not in c.get('domain', '')]
		if keep:
			await context.add_cookies(keep)


def is_page_alive(page) -> bool:
	"""检查页面是否仍然存活"""
	try:
		_ = page.url
		return not page.is_closed()
	except Exception:
		return False


async def ensure_page(context, page):
	"""确保有一个可用的页面，如果当前页面已关闭则新建"""
	if is_page_alive(page):
		return page
	print('检测到页面已关闭，正在新建标签页...')
	return await context.new_page()


async def refresh_single_account(context, page, account: dict, index: int, total: int, site: str = 'anyrouter.top') -> tuple[dict | None, any]:
	"""在浏览器中刷新单个账号的 session

	返回 (新账号配置, 当前page)，page 可能因重建而改变。
	"""
	display_name = get_account_display_name(account, index)
	print(f'\n--- 刷新账号 {index + 1}/{total} ({site}): {display_name} ---')

	try:
		page = await ensure_page(context, page)

		# 清除站点的 cookies（保留 GitHub 登录状态）
		await clear_site_cookies(context, site)

		# 导航到登录页面（带重试和手动导航兜底）
		print('正在导航到登录页面...')
		goto_ok = False
		for attempt in range(3):
			try:
				await page.goto(f'https://{site}/login', wait_until='networkidle', timeout=30000)
				goto_ok = True
				break
			except Exception as e:
				print(f'  导航失败 (尝试 {attempt + 1}/3): {e}')
				if attempt < 2:
					print('  等待 3 秒后重试...')
					await page.wait_for_timeout(3000)

		if not goto_ok:
			print(f'\n⚠️  自动导航失败，请在浏览器中手动打开 https://{site}/login')
			print('完成后按回车继续...')
			await asyncio.get_event_loop().run_in_executor(None, input)

		# 等待 WAF 通过
		try:
			await page.wait_for_function('document.readyState === "complete"', timeout=10000)
		except Exception:
			await page.wait_for_timeout(5000)

		print()
		print('请在浏览器中完成 GitHub 登录')
		print('（如需切换 GitHub 账号，请先在 GitHub 页面退出当前账号）')
		print('登录完成后，脚本会自动检测。如果长时间未检测到，请按回车...')

		# 等待登录完成：检测页面跳转到 console/dashboard
		try:

			async def wait_for_navigation():
				while True:
					if not is_page_alive(page):
						return False
					current_url = page.url
					if '/console' in current_url or '/dashboard' in current_url or '/panel' in current_url:
						return True
					await asyncio.sleep(1)

			async def wait_for_enter():
				await asyncio.get_event_loop().run_in_executor(None, input)
				return True

			done, pending = await asyncio.wait(
				[
					asyncio.create_task(wait_for_navigation()),
					asyncio.create_task(wait_for_enter()),
				],
				return_when=asyncio.FIRST_COMPLETED,
			)

			for task in pending:
				task.cancel()

		except Exception:
			pass

		# 确保页面还活着
		if not is_page_alive(page):
			print(f'❌ 账号 {index + 1} 页面已关闭')
			return None, page

		# 等待页面稳定
		await page.wait_for_timeout(2000)

		# 确保在正确的域名页面上
		if site not in page.url:
			await page.goto(f'https://{site}/console', wait_until='networkidle', timeout=0)
			await page.wait_for_timeout(2000)

		# 提取 session cookie
		cookies = await context.cookies(f'https://{site}')
		session_cookie = next((c for c in cookies if c['name'] == 'session'), None)

		if not session_cookie:
			print(f'❌ 账号 {index + 1} 未能提取到 session cookie')
			return None, page

		session_value = session_cookie['value']

		# api_user 不会变，直接沿用原有值
		api_user = account.get('api_user', '')

		# 用 API 验证 session 有效性并查询余额
		print('正在验证 session...')
		user_info = await page.evaluate(f"""
			async () => {{
				try {{
					const resp = await fetch('/api/user/self', {{
						headers: {{'new-api-user': '{api_user}'}},
						credentials: 'include'
					}});
					return await resp.json();
				}} catch (e) {{
					return {{success: false, error: e.toString()}};
				}}
			}}
		""")

		if user_info.get('success') and user_info.get('data'):
			quota = round(user_info['data'].get('quota', 0) / 500000, 2)
			used_quota = round(user_info['data'].get('used_quota', 0) / 500000, 2)
			print(f'   余额: ${quota}, 已用: ${used_quota}')
		else:
			print('   (余额查询失败，不影响 session 刷新)')

		# 组装新的账号配置
		new_account = {
			'cookies': {'session': session_value},
			'api_user': api_user,
		}

		if 'name' in account:
			new_account['name'] = account['name']

		session_preview = session_value[:8] + '...' + session_value[-8:] if len(session_value) > 20 else session_value
		print(f'\n✅ 账号 {index + 1} session 刷新成功！')
		print(f'   Session: {session_preview}')

		return new_account, page

	except Exception as e:
		print(f'❌ 账号 {index + 1} 刷新失败: {e}')
		return None, page


def update_env_file(env_var: str, new_accounts_json: str):
	"""更新 .env 文件中的指定环境变量"""
	env_path = Path(ENV_FILE)

	if not env_path.exists():
		env_path.write_text(f'{env_var}={new_accounts_json}\n', encoding='utf-8')
		return

	lines = env_path.read_text(encoding='utf-8').splitlines(keepends=True)
	new_lines = []
	found = False
	for line in lines:
		if line.startswith(f'{env_var}='):
			new_lines.append(f'{env_var}={new_accounts_json}\n')
			found = True
		else:
			new_lines.append(line)

	if not found:
		new_lines.append(f'{env_var}={new_accounts_json}\n')

	env_path.write_text(''.join(new_lines), encoding='utf-8')


def update_github_secret(secret_name: str, new_accounts_json: str) -> bool:
	"""使用 gh CLI 更新 GitHub Secret"""
	try:
		result = subprocess.run(
			['gh', 'secret', 'set', secret_name, '--env', 'production', '--body', new_accounts_json],
			capture_output=True,
			text=True,
			timeout=30,
		)
		if result.returncode == 0:
			return True
		else:
			print(f'gh 命令执行失败: {result.stderr}')
			return False
	except FileNotFoundError:
		print('未找到 gh CLI，请先安装: https://cli.github.com/')
		return False
	except subprocess.TimeoutExpired:
		print('gh 命令执行超时')
		return False


async def main():
	# 解析命令行参数
	site_filter = None
	if len(sys.argv) > 1:
		arg = sys.argv[1].lower()
		match = [s for env_var, s in SITE_CONFIGS if arg in s or arg in env_var.lower()]
		if match:
			site_filter = match[0]
		else:
			print(f'❌ 未知站点: {arg}')
			print(f'可选: {", ".join(s for _, s in SITE_CONFIGS)}')
			sys.exit(1)

	print()
	print('=== Session 刷新工具（支持多站点）===')
	if site_filter:
		print(f'    仅刷新: {site_filter}')
	print()

	# 筛选站点配置
	configs = [(ev, s) for ev, s in SITE_CONFIGS if site_filter is None or s == site_filter]

	# 读取账号配置
	sites_to_process = []
	for env_var, site in configs:
		accounts = load_existing_accounts(env_var)
		if accounts:
			sites_to_process.append((env_var, site, accounts))
			print(f'找到 {site} 的 {len(accounts)} 个账号配置')

	if not sites_to_process:
		print('❌ 未找到任何账号配置，请确保 .env 文件中包含 ANYROUTER_ACCOUNTS 或 AGENTROUTER_ACCOUNTS')
		sys.exit(1)

	# 确保浏览器配置目录存在
	os.makedirs(BROWSER_PROFILE_DIR, exist_ok=True)

	# 配置代理
	proxy_config = None
	proxy_url = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
	if proxy_url:
		proxy_config = {'server': proxy_url}

	is_first_run = not any(Path(BROWSER_PROFILE_DIR).iterdir()) if Path(BROWSER_PROFILE_DIR).exists() else True
	if is_first_run:
		print('首次运行，需要在浏览器中完整登录 GitHub（后续运行会自动保留登录状态）')
	print('正在启动浏览器...')

	async with async_playwright() as p:
		context = await p.chromium.launch_persistent_context(
			user_data_dir=BROWSER_PROFILE_DIR,
			channel='chrome',
			headless=False,
			ignore_https_errors=True,
			proxy=proxy_config,
			viewport={'width': 1280, 'height': 900},
			args=[
				'--disable-blink-features=AutomationControlled',
			],
		)

		page = context.pages[0] if context.pages else await context.new_page()

		# 收集各站点的刷新结果
		site_results = []

		for env_var, site, accounts in sites_to_process:
			print(f'\n{"=" * 40}')
			print(f'  处理站点: {site} ({len(accounts)} 个账号)')
			print(f'{"=" * 40}')

			new_accounts = []
			success_count = 0

			for i, account in enumerate(accounts):
				result, page = await refresh_single_account(context, page, account, i, len(accounts), site)
				if result:
					new_accounts.append(result)
					success_count += 1
				else:
					print(f'⚠️  保留账号 {i + 1} 的原有配置')
					new_accounts.append(account)

			site_results.append((env_var, site, accounts, new_accounts, success_count))

		await context.close()

	# 汇总并保存
	print()
	print('=== 全部完成 ===')

	has_success = False
	for env_var, site, accounts, new_accounts, success_count in site_results:
		print(f'{site}: ✅ 成功 {success_count}/{len(accounts)}')
		if success_count > 0:
			has_success = True

	if not has_success:
		print('❌ 没有账号刷新成功，不更新配置')
		sys.exit(1)

	# 更新本地 .env 文件（每个站点分别更新）
	for env_var, site, accounts, new_accounts, success_count in site_results:
		if success_count > 0:
			new_accounts_json = json.dumps(new_accounts, ensure_ascii=False, separators=(',', ':'))
			update_env_file(env_var, new_accounts_json)
			print(f'已更新本地 .env 文件: {env_var}')

	# 可选：更新 GitHub Secret
	print()
	try:
		answer = input('是否更新 GitHub Secret? [y/N]: ').strip().lower()
	except (EOFError, KeyboardInterrupt):
		answer = 'n'

	if answer == 'y':
		for env_var, site, accounts, new_accounts, success_count in site_results:
			if success_count > 0:
				new_accounts_json = json.dumps(new_accounts, ensure_ascii=False, separators=(',', ':'))
				print(f'正在更新 GitHub Secret: {env_var}...')
				if update_github_secret(env_var, new_accounts_json):
					print(f'✅ {env_var} GitHub Secret 已更新！')
				else:
					print(f'❌ {env_var} GitHub Secret 更新失败，请手动更新')
					print(f"   gh secret set {env_var} --env production --body '{new_accounts_json}'")


if __name__ == '__main__':
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n已取消')
		sys.exit(1)
