#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import argparse
import asyncio
import hashlib
import json
import os
import random
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from playwright.async_api import async_playwright

load_dotenv()

BROWSER_PROFILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.browser_profile')
ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')


def _is_headless_env() -> bool:
	"""systemd/cron 等无界面环境：无 DISPLAY 时自动使用 headless"""
	if os.getenv('HEADLESS', '').lower() in ('1', 'true', 'yes'):
		return True
	return not bool(os.getenv('DISPLAY'))


def _update_env_account(env_var: str, accounts: list, index: int, updated_account: dict):
	"""更新 .env 中指定账号的配置"""
	new_accounts = list(accounts)
	new_accounts[index] = updated_account
	new_json = json.dumps(new_accounts, ensure_ascii=False)
	path = Path(ENV_FILE)
	if not path.exists():
		path.write_text(f'{env_var}={new_json}\n', encoding='utf-8')
		return
	lines = path.read_text(encoding='utf-8').splitlines(keepends=True)
	out = []
	found = False
	for line in lines:
		if line.startswith(f'{env_var}='):
			out.append(f'{env_var}={new_json}\n')
			found = True
		else:
			out.append(line)
	if not found:
		out.append(f'{env_var}={new_json}\n')
	path.write_text(''.join(out), encoding='utf-8')


async def _clear_site_cookies(context, site: str):
	"""清除指定站点 cookies，保留 GitHub 登录状态"""
	try:
		await context.clear_cookies(domain=site)
	except TypeError:
		all_cookies = await context.cookies()
		await context.clear_cookies()
		keep = [c for c in all_cookies if site not in c.get('domain', '')]
		if keep:
			await context.add_cookies(keep)


async def _human_delay(min_ms: int = 500, max_ms: int = 1500):
	"""随机延迟，模拟人类操作节奏"""
	await asyncio.sleep(random.uniform(min_ms / 1000, max_ms / 1000))

from notify import notify

BALANCE_HASH_FILE = 'balance_hash.txt'


def load_accounts(provider_filter: str | None = None):
	"""从环境变量加载多账号配置（支持多站点）

	Args:
		provider_filter: 可选，'anyrouter' 或 'agentrouter' 时仅加载该站点的账号
	"""
	site_configs = [
		('ANYROUTER_ACCOUNTS', 'anyrouter.top', 'anyrouter'),
		('AGENTROUTER_ACCOUNTS', 'agentrouter.org', 'agentrouter'),
	]

	# CI 下默认跳过 AgentRouter（阿里云 WAF 拦截数据中心 IP）；配了 HTTP_PROXY 时可设 SKIP_AGENTROUTER_IN_CI=false 启用
	if os.getenv('GITHUB_ACTIONS') and os.getenv('SKIP_AGENTROUTER_IN_CI', 'true').lower() in ('true', '1', 'yes'):
		site_configs = [(ev, site, name) for ev, site, name in site_configs if name == 'anyrouter']

	# 按 provider 过滤
	if provider_filter:
		site_configs = [(ev, site, name) for ev, site, name in site_configs if name == provider_filter]
		if not site_configs:
			print(f"ERROR: Unknown provider '{provider_filter}', use 'anyrouter' or 'agentrouter'")
			return None

	all_accounts = []
	for env_var, site, _ in site_configs:
		accounts_str = os.getenv(env_var)
		if not accounts_str:
			continue

		try:
			accounts_data = json.loads(accounts_str)

			if not isinstance(accounts_data, list):
				print(f'ERROR: {env_var} must use array format [{{}}]')
				continue

			valid = True
			for i, account in enumerate(accounts_data):
				if not isinstance(account, dict):
					print(f'ERROR: {env_var} account {i + 1} configuration format is incorrect')
					valid = False
					break
				if 'cookies' not in account or 'api_user' not in account:
					print(f'ERROR: {env_var} account {i + 1} missing required fields (cookies, api_user)')
					valid = False
					break
				if 'name' in account and not account['name']:
					print(f'ERROR: {env_var} account {i + 1} name field cannot be empty')
					valid = False
					break

			if valid:
				for account in accounts_data:
					account['_site'] = site
					all_accounts.append(account)
		except Exception as e:
			print(f'ERROR: {env_var} configuration format is incorrect: {e}')

	if not all_accounts:
		print('ERROR: No valid account configuration found (check ANYROUTER_ACCOUNTS or AGENTROUTER_ACCOUNTS)')
		return None

	return all_accounts


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
	"""获取账号显示名称，优先使用 name 而非 id/api_user"""
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


async def _agentrouter_relogin_checkin(
	account_name: str, api_user: str, account: dict,
	env_var: str, site_accounts: list, site_index: int,
	*,
	debug: bool = False,
) -> tuple[bool, dict | None]:
	"""AgentRouter 自动重登以触发签到：用持久化 profile，清 cookie → 点 GitHub 登录 → 选账号 → 回跳"""
	masked_name = mask_sensitive_info(account_name)
	site = 'agentrouter.org'
	profile_dir = Path(BROWSER_PROFILE_DIR)

	if not profile_dir.exists() or not any(profile_dir.iterdir()):
		print(f'[WARN] {masked_name}: .browser_profile 为空，请先运行 uv run refresh_session.py agentrouter 完成首次登录')
		return False, None

	proxy_url = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
	proxy_config = {'server': proxy_url} if proxy_url else None

	async with async_playwright() as p:
		headless = _is_headless_env()
		if headless:
			print(f'[INFO] {masked_name}: 无界面环境，使用 headless 模式')
		launch_opts = dict(
			user_data_dir=str(profile_dir),
			headless=headless,
			ignore_https_errors=True,
			proxy=proxy_config,
			viewport={'width': 1280, 'height': 900},
			args=[
				'--disable-blink-features=AutomationControlled',
				'--no-sandbox',
			],
		)
		try:
			context = await p.chromium.launch_persistent_context(channel='chrome', **launch_opts)
		except Exception:
			context = await p.chromium.launch_persistent_context(**launch_opts)
		page = context.pages[0] if context.pages else await context.new_page()

		try:
			# 1. 清除 AgentRouter cookies（等效退出）
			print(f'[PROCESSING] {masked_name}: 清除 session，准备重新登录...')
			await _clear_site_cookies(context, site)
			await _human_delay(500, 1200)

			# 2. 进入登录页
			await page.goto(f'https://{site}/login', wait_until='networkidle')
			await page.wait_for_timeout(2000)

			# 3. 点击「Login with GitHub」（避免点到 New API 文档等无关链接）
			# 优先：同域 OAuth 路径 /api/oauth/github，或直连 github.com；排除 newapi.ai 等文档站
			github_selectors = [
				'a[href*="/api/oauth/github"]',
				'a[href^="/api/oauth/github"]',
				'a[href*="github.com/login/oauth"]',
				'a[href*="github.com"][href*="oauth"]',
				'button:has-text("GitHub")',
				'a:has-text("GitHub"):not([href*="newapi"])',
				'a:has-text("Login with GitHub"):not([href*="newapi"])',
			]
			clicked = False
			oauth_href = None
			for sel in github_selectors:
				try:
					loc = page.locator(sel).first
					if await loc.count() > 0:
						href = await loc.get_attribute('href')
						# 排除指向文档站的链接
						if href and any(x in (href or '').lower() for x in ['newapi.ai', 'newapi.pro', 'apifox', 'docs.']):
							continue
						oauth_href = href
						await loc.click(timeout=3000)
						clicked = True
						break
				except Exception:
					continue
			if not clicked:
				print(f'[FAILED] {masked_name}: 未找到 GitHub 登录按钮，请检查页面')
				await context.close()
				return False, None

			print(f'[PROCESSING] {masked_name}: 已点击 GitHub 登录，等待跳转...')
			# 4. 等待 GitHub 跳转（可能当前页跳转，也可能在新标签页打开）
			await page.wait_for_timeout(4000)
			# 若在新标签打开，切换到含 github.com 的页
			for p in context.pages:
				if 'github.com' in p.url:
					page = p
					if debug:
						print(f'[DEBUG] 使用新标签页: {page.url[:70]}')
					break
			# 若仍在 agentrouter，尝试直接打开 OAuth 链接（点击未触发导航时）
			if f'{site}' in page.url and 'github.com' not in page.url and oauth_href:
				nav_url = oauth_href if oauth_href.startswith('http') else f'https://{site}{oauth_href}' if oauth_href.startswith('/') else f'https://{site}/{oauth_href}'
				print(f'[PROCESSING] {masked_name}: 点击未跳转，直接访问 OAuth: {nav_url[:60]}...')
				await page.goto(nav_url, wait_until='domcontentloaded', timeout=15000)
			try:
				await page.wait_for_load_state('networkidle', timeout=12000)
			except Exception:
				await page.wait_for_load_state('domcontentloaded')
			await page.wait_for_timeout(2000)
			# 默认用 name 匹配 GitHub 账号，可显式配 github_login 覆盖
			github_login = (account.get('github_login') or account.get('name') or '').strip()
			if github_login:
				print(f'[PROCESSING] {masked_name}: 将匹配 GitHub 账号 {github_login!r}')
			else:
				print(f'[PROCESSING] {masked_name}: 在 GitHub 页面，自动查找并点击...')
			if debug:
				print(f'[DEBUG] 当前页面: {page.url}')

			async def _try_github_continue():
				"""GitHub /login/oauth/select_account 页结构：
				第一行：Signed in as X，form[action*=authorize_app] + input value=Continue；
				其他行：strong 为用户名，form[action*=switch_account] + input value=Select。
				匹配 name 后点击对应 Continue 或 Select；Select 会刷新页再点 Continue。
				"""
				r = await page.evaluate("""
					(args) => {
						const hint = (args && args.github_login) ? String(args.github_login).trim().toLowerCase() : '';
						const rows = document.querySelectorAll('.Box .Box-row');
						for (const row of rows) {
							const txt = (row.textContent || '').toLowerCase();
							if (/use a different account|use another/.test(txt)) continue;
							const hasMatch = hint && txt.includes(hint);
							const contForm = row.querySelector('form[action*="authorize_app"]');
							const switchForm = row.querySelector('form[action*="switch_account"]');
							if (contForm) {
								if (!hint || hasMatch) {
									const btn = contForm.querySelector('input[type="submit"], button[type="submit"]');
									if (btn && /continue/i.test(btn.value || btn.textContent || ''))
										{ btn.click(); return {ok: true, action: 'continue'}; }
								}
							}
							if (switchForm && hasMatch) {
								const btn = switchForm.querySelector('input[type="submit"], button[type="submit"]');
								if (btn) { btn.click(); return {ok: true, action: 'select'}; }
							}
						}
						if (!hint) {
							const first = document.querySelector('form[action*="authorize_app"] input[type="submit"]');
							if (first && first.value === 'Continue') { first.click(); return {ok: true, action: 'continue'}; }
						}
						return {ok: false};
					}
				""", {'github_login': github_login})
				return r

			for step in range(60):
				url = page.url
				if debug and step % 3 == 0:
					print(f'[DEBUG] step={step} url={url[:90]}')
				# 已回到 agentrouter 且不在登录页即视为成功（含 /console /dashboard /panel 或根路径）
				if site in url and '/login' not in url:
					break
				if 'github.com' in url:
					try:
						if debug and step % 5 == 0:
							diag = await page.evaluate("""
								(args) => {
									const hint = (args && args.github_login) ? String(args.github_login) : '';
									const rows = document.querySelectorAll('.Box .Box-row');
									const rowInfos = [];
									rows.forEach((r, i) => {
										const t = (r.textContent || '').substring(0, 80);
										const cont = r.querySelector('form[action*="authorize_app"]');
										const sw = r.querySelector('form[action*="switch_account"]');
										rowInfos.push({i, preview: t.replace(/\\s+/g,' ').trim(), hasContinue: !!cont, hasSelect: !!sw});
									});
									return {url: location.href, hint, rowCount: rows.length, rows: rowInfos};
								}
							""", {'github_login': github_login})
							print(f'[DEBUG] step={step} url={url[:80]}')
							print(f'[DEBUG] hint={diag.get("hint")!r} rows={diag.get("rowCount")} {diag.get("rows")}')
							await page.screenshot(path='debug_github.png')
							print(f'[DEBUG] 已保存 debug_github.png')
						r = await _try_github_continue()
						if debug:
							print(f'[DEBUG] step={step} _try_github_continue => {r}')
						if r.get('ok'):
							await page.wait_for_timeout(4000)  # 等待跳转
							if 'github.com' not in page.url:
								break
							# 若仍在 github，可能有多步，短暂等待后继续
							await page.wait_for_timeout(1500)
						else:
							await page.wait_for_timeout(1000)
					except Exception as e:
						if debug:
							print(f'[DEBUG] 异常: {e}')
						await page.wait_for_timeout(1000)
				else:
					await page.wait_for_timeout(1000)

			# 5. 已回到 agentrouter（非登录页），等待页面稳定
			await page.wait_for_timeout(2000)

			# 6. 提取新 session 并获取用户信息
			cookies = await context.cookies(f'https://{site}')
			session_cookie = next((c for c in cookies if c['name'] == 'session'), None)
			if not session_cookie:
				print(f'[FAILED] {masked_name}: 未能提取新 session')
				await context.close()
				return False, None

			user_info_result = await page.evaluate(f"""
				async () => {{
					try {{
						const r = await fetch('https://{site}/api/user/self', {{
							headers: {{'Accept': 'application/json', 'new-api-user': '{api_user}'}},
							credentials: 'include'
						}});
						const text = await r.text();
						return {{ ok: r.ok, text }};
					}} catch (e) {{ return {{ ok: false, text: e.toString() }}; }}
				}}
			""")

			await context.close()

			if not user_info_result.get('ok'):
				return False, None
			data = json.loads(user_info_result.get('text', '{}'))
			if not data.get('success') or not data.get('data'):
				return False, None
			ud = data['data']
			quota = round(ud.get('quota', 0) / 500000, 2)
			used = round(ud.get('used_quota', 0) / 500000, 2)
			user_info = {
				'success': True,
				'quota': quota,
				'used_quota': used,
				'display': f':money: Current balance: ${quota}, Used: ${used}',
			}
			print(user_info['display'])
			print(f'[SUCCESS] {masked_name}: 重登成功，签到已触发')

			# 7. 更新 .env 中的 session
			updated = {**account, 'cookies': {'session': session_cookie['value']}, 'api_user': api_user}
			if 'name' in account:
				updated['name'] = account['name']
			_update_env_account(env_var, site_accounts, site_index, updated)

			return True, user_info
		except Exception as e:
			await context.close()
			print(f'[FAILED] {masked_name}: 重登异常: {e}')
			raise


async def check_in_with_playwright(account_name: str, user_cookies: dict, api_user: str, site: str = 'anyrouter.top', agentrouter_update=None, debug=False):
	"""使用 Playwright 执行完整的签到流程

	agentrouter_update: 当 site 为 agentrouter 时传入 (env_var, site_accounts, site_index)，用于重登后更新 .env
	"""
	masked_name = mask_sensitive_info(account_name)
	print(f'[PROCESSING] {masked_name}: Starting browser for check-in...')

	# AgentRouter：走自动重登流程触发签到
	if site == 'agentrouter.org' and agentrouter_update:
		env_var, site_accounts, site_index = agentrouter_update
		account = site_accounts[site_index]
		return await _agentrouter_relogin_checkin(account_name, api_user, account, env_var, site_accounts, site_index, debug=debug)

	async with async_playwright() as p:
		import tempfile
		with tempfile.TemporaryDirectory() as temp_dir:
			# 配置代理（如果设置了环境变量）
			proxy_config = None
			proxy_url = os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
			if proxy_url:
				proxy_config = {'server': proxy_url}

			# 防自动化检测：禁用特征、模拟真实浏览器指纹
			headless = _is_headless_env()
			if headless:
				print(f'[INFO] {masked_name}: 无界面环境，使用 headless 模式')
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=headless,
				ignore_https_errors=True,
				proxy=proxy_config,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				locale='zh-CN',
				timezone_id='Asia/Shanghai',
				args=[
					'--disable-blink-features=AutomationControlled',  # 隐藏 webdriver 特征
					'--disable-automation',
					'--disable-infobars',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
					'--no-first-run',
					'--no-default-browser-check',
				],
			)

			page = await context.new_page()

			# 注入脚本：移除 navigator.webdriver 自动化标识（真实浏览器中为 false）
			await page.add_init_script("""
				Object.defineProperty(navigator, 'webdriver', { get: () => false });
			""")

			try:
				# 步骤1：访问登录页面获取 WAF cookies
				print(f'[PROCESSING] {masked_name}: Accessing login page to get WAF cookies...')
				await page.goto(f'https://{site}/login', wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				await _human_delay(800, 2000)

				# 步骤2：设置用户 cookies
				print(f'[PROCESSING] {masked_name}: Setting user cookies...')
				cookie_list = []
				for name, value in user_cookies.items():
					cookie_list.append({
						'name': name,
						'value': value,
						'domain': site,
						'path': '/',
					})
				await context.add_cookies(cookie_list)
				await _human_delay(500, 1200)

				# 步骤3：访问控制台页面确保登录状态
				print(f'[PROCESSING] {masked_name}: Accessing console page...')
				await page.goto(f'https://{site}/console', wait_until='networkidle')
				await page.wait_for_timeout(2000)
				await _human_delay(1000, 2500)

				# 步骤4：使用浏览器的 fetch API 获取用户信息
				print(f'[PROCESSING] {masked_name}: Getting user info...')
				user_info_result = await page.evaluate(f"""
					async () => {{
						try {{
							const response = await fetch('https://{site}/api/user/self', {{
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
						resp_text = user_info_result.get('text', '')
						preview = (resp_text[:300] + '...') if len(resp_text) > 300 else resp_text
						preview = preview.replace('\n', ' ')[:250]
						print(f'[WARN] {masked_name}: Failed to parse user info: {str(e)[:50]}')
						print(f'[DEBUG] {masked_name}: Response preview: {preview!r}')
				else:
					status = user_info_result.get('status', '?')
					err = user_info_result.get('error', user_info_result.get('text', '')[:100])
					print(f'[WARN] {masked_name}: User info request failed (HTTP {status}): {err}')

				await _human_delay(300, 800)

				# AnyRouter: 调用 sign_in 接口执行签到
				await _human_delay(500, 1500)
				print(f'[NETWORK] {masked_name}: Executing check-in (sign_in)')
				checkin_result = await page.evaluate(f"""
					async () => {{
						try {{
							const response = await fetch('https://{site}/api/user/sign_in', {{
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

				# 处理 AnyRouter 签到结果
				if checkin_result.get('success'):
					try:
						result = json.loads(checkin_result['text'])
						if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
							print(f'[SUCCESS] {masked_name}: Check-in successful!')
							return True, user_info
						else:
							error_msg = result.get('msg', result.get('message', 'Unknown error'))
							# 已签到过也算成功
							if any(kw in str(error_msg).lower() for kw in ['已签到', '已经签到', '重复签到', 'already checked', 'already signed']):
								print(f'[SUCCESS] {masked_name}: Already checked in today')
								return True, user_info
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
				await context.close()
				# 可重试的临时性错误向上抛出，由 check_in_account 重试
				if _is_retryable_error(str(e)):
					raise
				print(f'[FAILED] {masked_name}: Error during check-in: {str(e)[:100]}')
				return False, None


def _is_retryable_error(error_msg: str) -> bool:
	"""判断是否为可重试的临时性错误"""
	lower = str(error_msg).lower()
	return any(
		kw in lower
		for kw in [
			'timeout',
			'err_http_response_code',
			'err_connection',
			'err_network',
			'net::err',
		]
	)


async def check_in_account(account_info, account_index, agentrouter_update=None, debug=False):
	"""为单个账号执行签到操作（含失败重试）

	agentrouter_update: (env_var, site_accounts, site_index)，仅 AgentRouter 需要，用于重登后更新 .env
	"""
	account_name = get_account_display_name(account_info, account_index)
	masked_name = mask_sensitive_info(account_name)
	print(f'\n[PROCESSING] Starting to process {masked_name}')

	# 解析账号配置
	cookies_data = account_info.get('cookies', {})
	api_user = account_info.get('api_user', '')
	site = account_info.get('_site', 'anyrouter.top')

	if not api_user:
		print(f'[FAILED] {masked_name}: API user identifier not found')
		return False, None

	# 解析用户 cookies（AgentRouter 走重登流程时也会用到，但会先清 cookie）
	user_cookies = parse_cookies(cookies_data)
	if not user_cookies and site != 'agentrouter.org':
		print(f'[FAILED] {masked_name}: Invalid configuration format')
		return False, None

	max_retries = 2  # 最多重试 2 次（共 3 次尝试）
	retry_delay = 10  # 重试间隔（秒）
	last_error = None

	for attempt in range(max_retries + 1):
		try:
			success, user_info = await check_in_with_playwright(
				account_name, user_cookies, api_user, site,
				agentrouter_update=agentrouter_update,
				debug=debug,
			)
			if success:
				return True, user_info
			# 非异常返回的失败（如 API 返回错误），不重试
			return False, user_info
		except Exception as e:
			last_error = e
			if attempt < max_retries and _is_retryable_error(str(e)):
				print(f'[RETRY] {masked_name}: Attempt {attempt + 1} failed, retrying in {retry_delay}s... ({str(e)[:80]})')
				await asyncio.sleep(retry_delay)
			else:
				print(f'[FAILED] {masked_name}: Error during check-in: {str(e)[:100]}')
				return False, None

	print(f'[FAILED] {masked_name}: Error during check-in: {str(last_error)[:100]}')
	return False, None


def parse_args():
	"""解析命令行参数"""
	parser = argparse.ArgumentParser(
		description='AnyRouter/AgentRouter 多账号自动签到',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog='''
示例:
  uv run checkin.py                          # 全部账号
  uv run checkin.py --provider agentrouter    # 仅 agentrouter 的账号
  uv run checkin.py --provider anyrouter --index 1   # 仅 anyrouter 第 1 个账号
  uv run checkin.py --index 3                # 全部账号中的第 3 个（按 anyrouter 先、agentrouter 后）
		''',
	)
	parser.add_argument(
		'--provider',
		choices=['anyrouter', 'agentrouter'],
		help='仅测试指定提供商的账号',
	)
	parser.add_argument(
		'--index',
		type=int,
		metavar='N',
		help='仅测试第 N 个账号（从 1 开始），可与 --provider 组合使用',
	)
	parser.add_argument(
		'--debug',
		action='store_true',
		help='调试模式：打印 GitHub 页面诊断信息、保存 debug_github.png 截图，便于排查卡住问题',
	)
	return parser.parse_args()


async def main(args=None):
	"""主函数"""
	args = args or parse_args()

	print('[SYSTEM] Multi-site multi-account auto check-in script started (using Playwright)')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	# 加载账号配置（all_accounts 保留完整列表，用于更新 .env 时只替换单账号）
	all_accounts = load_accounts(provider_filter=args.provider)
	if not all_accounts:
		print('[FAILED] Unable to load account configuration, program exits')
		sys.exit(1)

	# 按 index 过滤
	if args.index is not None:
		if args.index < 1 or args.index > len(all_accounts):
			filter_hint = f' (--provider {args.provider})' if args.provider else ''
			print(f'[FAILED] Index must be 1-{len(all_accounts)}{filter_hint}, got {args.index}')
			print(f'[HINT] 当前共 {len(all_accounts)} 个账号，使用 --index 1 或省略 --index 运行全部')
			sys.exit(1)
		accounts = [all_accounts[args.index - 1]]
		print(f'[INFO] Testing single account: index {args.index} ({get_account_display_name(accounts[0], args.index - 1)})')
	else:
		accounts = all_accounts
		print(f'[INFO] Found {len(accounts)} account configurations')

	# 加载余额hash
	last_balance_hash = load_balance_hash()

	# AgentRouter 完整账号列表（用 all_accounts 构建，确保更新 .env 时只改当前账号、不覆盖其他）
	agentrouter_accounts = [a for a in all_accounts if a.get('_site') == 'agentrouter.org']

	# 为每个账号执行签到，并记录每个账号的结果用于通知
	success_count = 0
	total_count = len(accounts)
	check_results = []  # 存储每个账号的签到结果
	current_balances = {}
	need_notify = False  # 是否需要发送通知
	balance_changed = False  # 余额是否有变化

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		site = account.get('_site', 'anyrouter.top')
		agentrouter_update = None
		if site == 'agentrouter.org' and agentrouter_accounts:
			if args.index is not None:
				site_index = args.index - 1  # 单账号模式：第 N 个即 index N-1
			else:
				site_index = len([a for a in accounts[:i] if a.get('_site') == 'agentrouter.org'])
			agentrouter_update = ('AGENTROUTER_ACCOUNTS', agentrouter_accounts, site_index)
		try:
			success, user_info = await check_in_account(account, i, agentrouter_update=agentrouter_update, debug=args.debug)
			if success:
				success_count += 1

			# 如果签到失败，需要通知
			if not success:
				need_notify = True
				account_name = get_account_display_name(account, i)
				masked_name = mask_sensitive_info(account_name)
				print(f'[NOTIFY] {masked_name} failed, will send notification')

			# 收集余额数据
			if user_info and user_info.get('success'):
				current_quota = user_info['quota']
				current_used = user_info['used_quota']
				current_balances[account_key] = {'quota': current_quota, 'used': current_used}

			# 记录本账号签到结果
			check_results.append({
				'account': account,
				'index': i,
				'success': success,
				'user_info': user_info,
			})

		except Exception as e:
			account_name = get_account_display_name(account, i)
			masked_name = mask_sensitive_info(account_name)
			print(f'[FAILED] {masked_name} processing exception: {e}')
			need_notify = True  # 异常也需要通知
			check_results.append({
				'account': account,
				'index': i,
				'success': False,
				'user_info': None,
				'error': str(e)[:50],
			})

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

	# 构建通知内容：按 provider 分组，格式 {provider}: {name} : {balance} : {used}
	provider_lines = {}  # site -> [line1, line2, ...]
	if need_notify:
		for result in check_results:
			account = result['account']
			i = result['index']
			account_key = f'account_{i + 1}'
			account_name = get_account_display_name(account, i)
			masked_name = mask_sensitive_info(account_name)
			site = account.get('_site', 'anyrouter.top')
			success = result['success']

			if success and account_key in current_balances:
				quota = current_balances[account_key]['quota']
				used = current_balances[account_key]['used']
				line = f'{masked_name} : ${quota} : ${used}'
			elif success:
				line = f'{masked_name} : - : -'
			else:
				line = f'{masked_name} : 失败'

			provider_lines.setdefault(site, []).append(line)

	# 按 anyrouter 先、agentrouter 后排序
	site_order = ['anyrouter.top', 'agentrouter.org']
	notification_content = []
	for site in site_order:
		if site in provider_lines:
			notification_content.append(f'{site}:')
			notification_content.extend(provider_lines[site])

	# 保存当前余额hash（测试模式下跳过，避免影响后续完整运行的余额检测）
	if current_balance_hash and not (args.provider or args.index):
		save_balance_hash(current_balance_hash)

	test_mode = args.provider is not None or args.index is not None

	if need_notify and notification_content:
		time_info = f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
		notify_content = '\n'.join([time_info, ''] + notification_content)
		print(notify_content)
		if not test_mode:
			notify.push_message('AnyRouter Check-in Alert', notify_content, msg_type='text')
			print('[NOTIFY] Notification sent due to failures or balance changes')
		else:
			print('[INFO] Test mode: notification skipped')
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
