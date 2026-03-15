# AnyRouter / AgentRouter 多账号自动签到

推荐搭配使用[Auo](https://github.com/millylee/auo)，支持任意 Claude Code Token 切换的工具。

**维护开源不易，如果本项目帮助到了你，请帮忙点个 Star，谢谢!**

同时支持 [AnyRouter](https://anyrouter.top/register?aff=gSsN) 和 [AgentRouter](https://agentrouter.org/register?aff=CONH) 两个 Claude Code 中转站的多账号每日签到，一次 $25，限时注册即送 100 美金。业界良心，支持 Claude Sonnet 4.5、GPT-5-Codex、Claude Code 百万上下文（使用 `/model sonnet[1m]` 开启），`gemini-2.5-pro` 模型。

## 功能特性

- ✅ 单个/多账号自动签到
- ✅ 同时支持 anyrouter.top 和 agentrouter.org 两个站点
- ✅ 多种机器人通知（可选）
- ✅ 绕过 WAF 限制
- ✅ 失败自动重试（超时、网络错误等临时性问题）
- ✅ 本地单账号/提供商测试模式（`--provider`、`--index`）
- ✅ 防自动化检测（隐藏 webdriver 特征、随机延迟、模拟真实浏览器指纹）

## 使用方法

### 1. Fork 本仓库

点击右上角的 "Fork" 按钮，将本仓库 fork 到你的账户。

### 2. 获取账号信息

对于每个需要签到的账号，你需要获取：
1. **Cookies**: 用于身份验证
2. **API User**: 用于请求头的 new-api-user 参数

#### 获取 Cookies：
1. 打开浏览器，访问对应站点（https://anyrouter.top/ 或 https://agentrouter.org/）
2. 登录你的账户
3. 打开开发者工具 (F12)
4. 切换到 "Application" 或 "存储" 选项卡
5. 找到 "Cookies" 选项
6. 复制所有 cookies

#### 获取 API User：
通常在网站的用户设置或 API 设置中可以找到，每个账号都有唯一的标识。

### 3. 设置 GitHub Environment Secret

1. 在你 fork 的仓库中，点击 "Settings" 选项卡
2. 在左侧菜单中找到 "Environments" -> "New environment"
3. 新建一个名为 `production` 的环境
4. 点击新建的 `production` 环境进入环境配置页
5. 点击 "Add environment secret" 创建 secret：
   - Name: `ANYROUTER_ACCOUNTS`
   - Value: 你的 anyrouter.top 多账号配置数据
   - （可选）Name: `AGENTROUTER_ACCOUNTS`
   - （可选）Value: 你的 agentrouter.org 多账号配置数据

### 4. 多账号配置格式

支持单个与多个账号配置，可选 `name` 字段用于自定义账号显示名称。`ANYROUTER_ACCOUNTS` 和 `AGENTROUTER_ACCOUNTS` 格式完全一致：

```json
[
  {
    "name": "我的主账号",
    "cookies": {
      "session": "account1_session_value"
    },
    "api_user": "account1_api_user_id"
  },
  {
    "name": "备用账号",
    "cookies": {
      "session": "account2_session_value"
    },
    "api_user": "account2_api_user_id"
  }
]
```

**字段说明**：
- `cookies` (必需)：用于身份验证的 cookies 数据
- `api_user` (必需)：用于请求头的 new-api-user 参数
- `name` (可选)：自定义账号显示名称，用于通知和日志中标识账号

如果未提供 `name` 字段，会使用 `Account 1`、`Account 2` 等默认名称。

接下来获取 cookies 与 api_user 的值。

通过 F12 工具，切到 Application 面板，拿到 session 的值，最好重新登录下，该值 1 个月有效期，但有可能提前失效，失效后报 401 错误，到时请再重新获取。

![获取 cookies](./assets/request-session.png)

通过 F12 工具，切到 Network 面板，可以过滤下，只要 Fetch/XHR，找到带 `New-Api-User`，这个值正常是 5 位数，如果是负数或者个位数，正常是未登录。

![获取 api_user](./assets/request-api-user.png)

### 5. 启用 GitHub Actions

1. 在你的仓库中，点击 "Actions" 选项卡
2. 如果提示启用 Actions，请点击启用
3. 找到 "AnyRouter 自动签到" workflow
4. 点击 "Enable workflow"

### 6. 测试运行

你可以手动触发一次签到来测试：

1. 在 "Actions" 选项卡中，点击 "AnyRouter 自动签到"
2. 点击 "Run workflow" 按钮
3. 确认运行

![运行结果](./assets/check-in.png)

## 执行时间

- 脚本每6小时执行一次（1. action 无法准确触发，基本延时 1~1.5h；2. 目前观测到签到是每 24h 而不是零点就可签到）
- 两个站点的账号在同一次执行中依次签到
- 你也可以随时手动触发签到

## 注意事项

- 请确保每个账号的 cookies 和 API User 都是正确的
- 可以在 Actions 页面查看详细的运行日志
- 支持部分账号失败，只要有账号成功签到，整个任务就不会失败
- 只配置 `ANYROUTER_ACCOUNTS` 也能正常运行，`AGENTROUTER_ACCOUNTS` 为可选项
- **AgentRouter 与 AnyRouter 签到逻辑不同**：AgentRouter 在请求用户信息时自动完成签到，无需单独调用签到接口；AnyRouter 需调用签到接口
- **AgentRouter 访问**：若出现超时或 `ERR_HTTP_RESPONSE_CODE_FAILURE`，可能是地区限制。在环境变量或 `.env` 中配置 `HTTP_PROXY` 或 `http_proxy`（如 `http://127.0.0.1:7890`）使用代理
- 报 401 错误，请重新获取 cookies，理论 1 个月失效，但有 Bug，详见 [#6](https://github.com/millylee/anyrouter-check-in/issues/6)
- 请求 200，但出现 Error 1040（08004）：Too many connections，官方数据库问题，目前已修复，但遇到几次了，详见 [#7](https://github.com/millylee/anyrouter-check-in/issues/7)

## 配置示例

假设你有两个账号需要签到：

```json
[
  {
    "cookies": {
      "session": "abc123session"
    },
    "api_user": "user123"
  },
  {
    "cookies": {
      "session": "xyz789session"
    },
    "api_user": "user456"
  }
]
```

## 开启通知

脚本支持多种通知方式，可以通过配置以下环境变量开启，如果 `webhook` 有要求安全设置，例如钉钉，可以在新建机器人时选择自定义关键词，填写 `AnyRouter`。

### 邮箱通知
- `EMAIL_USER`: 发件人邮箱地址
- `EMAIL_PASS`: 发件人邮箱密码/授权码
- `CUSTOM_SMTP_SERVER`: 自定义发件人SMTP服务器(可选)
- `EMAIL_TO`: 收件人邮箱地址
### 钉钉机器人
- `DINGDING_WEBHOOK`: 钉钉机器人的 Webhook 地址

### 飞书机器人
- `FEISHU_WEBHOOK`: 飞书机器人的 Webhook 地址

### 企业微信机器人
- `WEIXIN_WEBHOOK`: 企业微信机器人的 Webhook 地址

### PushPlus 推送
- `PUSHPLUS_TOKEN`: PushPlus 的 Token

### Server酱
- `SERVERPUSHKEY`: Server酱的 SendKey

配置步骤：
1. 在仓库的 Settings -> Environments -> production -> Environment secrets 中添加上述环境变量
2. 每个通知方式都是独立的，可以只配置你需要的推送方式
3. 如果某个通知方式配置不正确或未配置，脚本会自动跳过该通知方式

## Session 刷新

Session cookie 每月会失效（报 401 错误）。本项目提供一个本地辅助脚本，简化 session 刷新流程：

```bash
# 刷新所有站点
uv run refresh_session.py

# 只刷新指定站点
uv run refresh_session.py anyrouter
uv run refresh_session.py agentrouter
```

脚本会打开一个持久化浏览器窗口，逐个站点、逐个账号操作：
1. 读取 `.env` 中的 `ANYROUTER_ACCOUNTS` 和 `AGENTROUTER_ACCOUNTS` 配置
2. 导航到对应站点登录页，用户手动完成 GitHub 登录
3. 自动提取新的 session cookie 和 api_user
4. 分别更新本地 `.env` 文件中的两个变量
5. 可选：通过 `gh` CLI 分别更新两个 GitHub Secret

浏览器配置保存在 `.browser_profile/` 目录，**首次运行**需要完整登录 GitHub，后续运行 GitHub 登录状态自动保留，只需点击「Login with GitHub」即可。

## AgentRouter CI 失败诊断

当 AgentRouter 在 GitHub Actions 中失败但本机成功时，可通过诊断流程获取根因：

1. **本机生成成功基线**：
   ```bash
   uv run python diagnose.py
   # 将 diagnostic.json 保存为 diagnostic-local.json
   ```

2. **在 GitHub 上运行诊断**：Actions →「诊断 AgentRouter」→ Run workflow

3. **对比结果**：运行完成后下载 artifact，对比两份 `diagnostic.json`：
   - `runner_ip`：CI 为数据中心 IP，本机为家用/公司 IP
   - `api_response.status`：HTTP 状态码
   - `api_response.text_start`：响应内容开头（HTML 表示被重定向到验证页，JSON 表示接口正常）
   - `steps`：哪一步失败（goto_login / goto_console）

根据对比结果判断：IP 限制、WAF 拦截、Cookie 传递问题等。

## 故障排除

如果签到失败，请检查：

1. 账号配置格式是否正确
2. cookies 是否过期
3. API User 是否正确
4. 网站是否更改了签到接口
5. 查看 Actions 运行日志获取详细错误信息

## 本地开发环境设置

如果你需要在本地测试或开发，请按照以下步骤设置：

```bash
# 安装所有依赖
uv sync --dev

# 安装 Playwright 浏览器
uv run playwright install chromium --with-deps

# 按 .env.example 创建 .env
uv run checkin.py
```

### 本地单账号/提供商测试

可指定只测试某个提供商或某个账号，便于调试：

```bash
# 全部账号
uv run checkin.py

# 仅 agentrouter 的账号
uv run checkin.py --provider agentrouter

# 仅 agentrouter 第 1 个账号
uv run checkin.py --provider agentrouter --index 1

# 仅 anyrouter 第 2 个账号
uv run checkin.py --provider anyrouter --index 2

# 全部账号中的第 3 个（按 anyrouter 先、agentrouter 后的顺序）
uv run checkin.py --index 3
```

测试模式下不会发送通知，也不会更新余额缓存，适合本地排查问题。

## 测试

```bash
uv sync --dev

# 安装 Playwright 浏览器
uv run playwright install chromium --with-deps

# 运行测试
uv run pytest tests/
```

## 免责声明

本脚本仅用于学习和研究目的，使用前请确保遵守相关网站的使用条款.
