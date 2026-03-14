# Session 刷新操作手册

AnyRouter 使用 GitHub OAuth 登录，session cookie 约 1 个月失效（报 401 错误）。本文档记录完整的 session 刷新流程。

## 前置准备（仅首次）

### 1. 安装依赖

```bash
uv sync --dev
playwright install chromium
```

### 2. 配置 gh CLI 多账号（如有多个 GitHub 账号）

```bash
# 登录第一个账号
gh auth login

# 登录额外账号
gh auth login

# 查看所有已登录账号
gh auth status

# 切换活跃账号
gh auth switch
```

### 3. 授权 gh CLI 环境 Secret 写入权限

更新 GitHub Secret 需要 `admin:org` scope：

```bash
gh auth refresh -s admin:org
```

## 刷新流程

### 步骤 1：运行刷新脚本

```bash
uv run refresh_session.py
```

脚本会：
1. 读取 `.env` 中的 `ANYROUTER_ACCOUNTS` 配置
2. 启动一个 Chrome 浏览器窗口（使用 `.browser_profile/` 持久化配置）
3. 逐个账号导航到 anyrouter 登录页

### 步骤 2：在浏览器中完成登录

对每个账号，脚本会打开 `anyrouter.top/login` 页面：

- **首次运行**：需要完整登录 GitHub（输入用户名、密码、2FA）
- **后续运行**：GitHub 登录状态已保留在 `.browser_profile/` 中，只需点击「Login with GitHub」
- **切换账号**：如需登录不同的 GitHub 账号，先在 GitHub 页面退出当前账号，再登录目标账号

登录成功后，脚本会自动检测页面跳转到 console 页面。如果自动检测失败，在终端按回车手动确认。

### 步骤 3：确认结果

每个账号刷新成功后会显示：

```
正在验证 session...
   余额: $25.0, 已用: $3.5

✅ 账号 1 session 刷新成功！
   Session: MTc3MzQ2...pz0k7w==
```

全部完成后，脚本会自动更新本地 `.env` 文件。

### 步骤 4：更新 GitHub Secret

脚本结束时会提示：

```
是否更新 GitHub Secret? [y/N]: y
```

输入 `y` 会通过 `gh secret set` 自动更新 `production` 环境的 Secret。

#### 如果自动更新失败

确认当前 gh CLI 已切换到正确的 GitHub 账号：

```bash
gh auth switch
```

手动更新：

```bash
gh secret set ANYROUTER_ACCOUNTS --env production < <(grep '^ANYROUTER_ACCOUNTS=' .env | cut -d= -f2-)
```

### 步骤 5：验证

```bash
# 本地验证 session 有效
uv run checkin.py

# 或触发 GitHub Actions 验证
gh repo set-default decker502/anyrouter-check-in
gh workflow run "AnyRouter 自动签到"
gh run list --limit 1
```

## 注意事项

- `.browser_profile/` 目录保存了浏览器配置（含 GitHub 登录状态），已在 `.gitignore` 中排除，不要提交到仓库
- 如果浏览器页面被意外关闭，脚本会自动新建标签页继续处理下一个账号
- 刷新失败的账号会保留原有配置，不会丢失
- `api_user` 不会变化，脚本直接沿用原有值，只刷新 session cookie
