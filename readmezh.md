## Cookie-Monster-BOF 中文使用说明

本项目提供一个用于 Cobalt Strike 的 BOF（Beacon Object File）与配套 Python 解密脚本，用于在已获授权的场景下，从 Windows 机器上的浏览器（Chrome、Edge、Firefox）提取 Cookies 与保存的账号密码，并进行离线解密与导出。

警告：本工具仅用于合规授权的渗透测试、红队评估与研究用途。请遵守所在国家/地区及组织的法律法规与合规要求。

### 目录结构概览
- `cookie-monster.cna`: Cobalt Strike Aggressor 脚本，注册并实现 `cookie-monster` 命令，负责参数解析与调用 BOF。
- `cookie-monster-bof.c` / `cookie-monster-bof.h`: BOF 核心源码（C 语言），执行进程与句柄枚举、文件复制/无文件下载、密钥提取等操作。
- `beacon.h`: Beacon API 头文件，供编译 BOF 使用。
- `decrypt.py`: Python 解密脚本，支持解密 Chromium Cookies/Passwords，输出多格式（文本、Cookie-Editor JSON、CuddlePhish 等）。
- `Makefile`: 交叉编译 BOF 的构建脚本，产出 `cookie-monster-bof.x86.o` 与 `cookie-monster-bof.x64.o`。
- `requirements.txt`: `decrypt.py` 所需 Python 依赖列表。

### 功能与特性
- 提取 Chromium（Chrome/Edge）的 WebKit Master Key 与 App Bound Encryption Key（适配 v20+ Cookies 方案）。
- 自动定位并复制 Cookies 与 Login Data 数据库，支持：
  - 自动枚举浏览器进程句柄，复制目标文件（支持 fileless 思路）。
  - 已知 PID 的精准复制模式（`--chromeCookiePID`/`--chromeLoginDataPID`/`--edgeCookiePID`/`--edgeLoginDataPID`）。
- 支持以 SYSTEM 身份解密 Chromium App Bound Key（无需注入浏览器进程）。
- Firefox：自动定位 `profiles.ini`，下载 `logins.json` 与 `key4.db`，离线解密参考外部工具。
- Python 侧离线解密、导出多种格式（文本、`cookie-editor`、`cuddlephish`、`firefox`）。

### 兼容性与版本变更
- Chromium 127+ 开始引入 v20 Cookie 加密，使用 app bound key；需在浏览器应用目录内运行或通过 `--system` 模式与模拟获得解密能力。
- 已适配 Chrome 137+ 对 PostProcessData 的变更，可在 SYSTEM 上下文完成解密（参见源码与 README 引用）。
- 目标平台为 Windows；BOF 编译通常在 Linux 交叉编译环境完成。

### 工作原理简述
1. 进程与句柄枚举：定位 `chrome.exe`/`msedge.exe`/Firefox 相关进程，寻找对 Cookies/Login Data 文件的有效句柄。
2. 句柄复制与文件获取：
   - fileless：复用句柄直接读取目标文件内容至内存，再落地到当前工作目录或按需复制到指定路径；
   - 常规复制：使用 `--copy-file` 直接复制。
3. 密钥提取：从浏览器的 `Local State` 与相关位置提取 WebKit Master Key 与 App Bound Key；在新版本下可能需要 AES Key 或在 SYSTEM 上下文完成解密。
4. 离线解密：通过 `decrypt.py` 结合密钥对数据库文件进行解密，输出明文或转换为 JSON 格式供后续使用。

### 快速开始
#### 1) 编译 BOF（在 Linux 上）
确保已安装 mingw-w64 与 make：
```bash
make
```
生成：
- `cookie-monster-bof.x64.o`
- `cookie-monster-bof.x86.o`

清理：
```bash
make clean
```
注意：如清理目标文件名与生成产物不一致，可手动删除对应 `.o` 文件。

#### 2) 在 Cobalt Strike 中加载脚本
- 在 CS 中加载 `cookie-monster.cna`。
- Beacon 中执行命令：`cookie-monster [参数]`。

#### 3) 获取到数据库文件与密钥后进行离线解密
安装依赖：
```bash
pip3 install -r requirements.txt
```
查看帮助：
```bash
python3 decrypt.py -h
```

### Cobalt Strike 命令与参数
`cookie-monster` 的完整帮助已在 `cookie-monster.cna` 与 `README.md` 中定义，摘要如下：

基础模式：
- `--chrome`：自动枚举进程与句柄，如匹配 `chrome.exe`，复制 Cookies/Login Data 文件到 CWD。
- `--edge`：同上，匹配 `msedge.exe`。
- `--firefox`：解析 `profiles.ini`，定位 `logins.json` 与 `key4.db` 并下载。

系统级解密（无注入）：
- `--system "C:\Users\<USER>\AppData\Local\<BROWSER>\User Data\Local State" <PID>`
  - 在 SYSTEM 上下文提取 app bound key；
  - 需要提供 `Local State` 路径与某用户进程的 PID 用于模拟；
  - 适用于 Chromium v20+、Chrome 137+ 场景。

精确到特定 PID：
- `--chromeCookiePID <PID>` / `--chromeLoginDataPID <PID>`
- `--edgeCookiePID <PID>` / `--edgeLoginDataPID <PID>`
  - 已知哪个进程持有目标文件句柄时，直接复用加速获取。

选择性获取：
- `--key-only`：仅获取 app bound key（不下载 Cookie/Login Data）。
- `--cookie-only`：仅下载 Cookie 文件。
- `--login-data-only`：仅下载 Login Data 文件。

复制方式：
- `--copy-file "C:\Folder\Location\"`：不走 fileless，直接复制到该目录。

参数互斥/校验（在 `.cna` 内已实现）：
- `--key-only` 不能与 `--cookie-only` 或 `--login-data-only` 同用。
- `--key-only` 不能与 `--copy-file` 同用。
- `--login-data-only` 不能与 `--edgeCookiePID`/`--chromeCookiePID` 同用。
- `--cookie-only` 不能与 `--edgeLoginDataPID`/`--chromeLoginDataPID` 同用。
- PID 必须为数字且不等于 1。

示例：
```text
cookie-monster --chrome
cookie-monster --edge
cookie-monster --system "C:\Users\<USER>\AppData\Local\Chrome\User Data\Local State" 1234
cookie-monster --chromeCookiePID 4321
cookie-monster --edgeLoginDataPID 5678 --login-data-only
cookie-monster --edge --copy-file "C:\loot\browser\"
```

### Python 解密脚本使用
安装：
```bash
pip3 install -r requirements.txt
```

基本用法：
```bash
python3 decrypt.py -h
```

重要参数：
- `-k/--key`：解密密钥（从 BOF 结果中获取）。
- `-o/--option`：输出/处理选项，支持 `cookies`、`passwords`、`cookie-editor`、`cuddlephish`、`firefox`。
- `-f/--file`：数据库文件位置（如 `ChromeCookies.db`、`ChromePasswords.db`）。
- `--chrome-aes-key`：可选，提供 Chrome AES Key，适配新版本解密流程（如 v20+/137+）。

常见示例：
```bash
# 文本输出 Cookies
python3 decrypt.py -k "\xec\xfc...." -o cookies -f ChromeCookies.db

# 文本输出 Passwords
python3 decrypt.py -k "\xec\xfc...." -o passwords -f ChromePasswords.db

# 生成 Cookie-Editor 插件可导入的 JSON
python3 decrypt.py -k "\xec\xfc...." -o cookie-editor -f ChromeCookies.db

# 提供 Chrome AES Key（适配 v20+/137+），输出 cuddlephish 所需 JSON
python3 decrypt.py --chrome-aes-key '\x8e\....' -k "\x03\...." -o cuddlephish -f ChromeCookies.db
```

输出示例（精简）：
```text
Host: .github.com
Path: /
Name: dotcom_user
Cookie: KingOfTheNOPs
Expires: Oct 28 2024 21:25:22
```

### 常见场景建议
- 仅需 Cookies：`--cookie-only` 可避免不必要的数据拉取，降低噪声与风险。
- 已知持句柄进程：优先使用 `--*PID` 精确参数，减少扫描与失败概率。
- 目标较新 Chrome/Edge：优先尝试 `--system` 并准备好 `Local State` 路径与有效用户进程 PID。
- 需要导入到浏览器插件或配合钓鱼框架：使用 `-o cookie-editor` 或 `-o cuddlephish`。

### 故障排查（Troubleshooting）
- 提示 `NO OPTIONS SELECTED`：未提供任何模式参数，请至少选择 `--chrome/--edge/--system/--firefox` 或 `--*PID`。
- `Invalid PID`：PID 非数字或为 `1`；请提供正确的用户进程 PID。
- `--key-only` 组合报错：与 `--cookie-only`/`--login-data-only`/`--copy-file` 互斥，选择其一。
- 无法获取 app bound key：
  - 确认运行目录与浏览器应用目录关系（对 v20+ 重要）；
  - 或切换到 `--system` 模式并提供正确 `Local State` 路径与 PID；
  - 如为 Chrome 137+，请结合 `--chrome-aes-key` 在解密脚本中处理。
- 解密脚本报依赖问题：重新执行 `pip3 install -r requirements.txt`，确保 Python 版本与架构匹配。

### OPSEC 与合规
- 仅在授权目标与限定时间窗口内操作，最小化对目标环境的影响；
- 使用 `--copy-file` 会在磁盘上产生痕迹，fileless 方式相对隐蔽但仍可能触发 EDR 检测；
- 对落地文件妥善保管并进行访问控制，确保数据最小化与加密存储；
- 全流程留痕审计，测试结束后及时清理临时与导出文件。

### FAQ
- Q: 是否必须注入浏览器进程？
  - A: 不必须。对于新版本，推荐 `--system` 方式获取 app bound key，从而避免注入。
- Q: 仅想要 Cookies，不关心密码？
  - A: 使用 `--cookie-only` 搭配相应浏览器参数即可。
- Q: Firefox 的解密如何做？
  - A: 脚本会帮助定位文件，解密参考外部项目 `firepwd`（链接见下）。

### 参考链接
- WebKit Master Key 提取（Mr-Un1k0d3r）
  - `https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF`
- 无文件下载思路（nanodump）
  - `https://github.com/fortra/nanodump`
- Cookies/Passwords 解密（DonPAPI）
  - `https://github.com/login-securite/DonPAPI`
- App Bound Key 解密思路（snovvcrash）
  - `https://gist.github.com/snovvcrash/caded55a318bbefcb6cc9ee30e82f824`
- Chrome 137+ v20 解密（runassu）
  - `https://github.com/runassu/chrome_v20_decryption`

---
如需我帮你：
- 在本机编译 BOF；
- 生成示例命令行；
- 或根据你的目标环境定制参数与流程；

请告诉我你的目标浏览器与可用权限（用户/管理员/SYSTEM）与已知 PID 信息。


