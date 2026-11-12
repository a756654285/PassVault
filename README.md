# PassVault

一个**完全离线**的本地密码保险库，Windows 免安装桌面版。数据用你的主密码加密后只存在本机，不联网、不上传、无账号、无遥测。

作者：[@a756654285](https://github.com/a756654285) · 源码与问题反馈：https://github.com/a756654285/PassVault

> 基于 Electron + Web Crypto，单页界面 + 一个加密文件，没有服务端、没有数据库服务、没有云同步。

## 特性

- **本地加密**：PBKDF2-SHA256（25 万次迭代）派生密钥，AES-GCM 256 加密每条记录
- **自动保存**：新增 / 编辑 / 删除 / 拖动后停顿约 0.6 秒自动加密落盘，重开软件自动恢复
- **分组管理**：分组栏可拖动排序，列表条目可拖动排序，顺序随库一起加密保存
- **完整迁移**：「数据库迁移」导出完整备份（含分组顺序），另一台电脑一键导入，支持不同主密码、覆盖或合并
- **远程连接**：条目可记录 RDP / SSH / Telnet 主机，一键拉起 mstsc、SecureCRT 或系统终端
- **分享单条**：生成 `.txt` / Word 明文文件（需先输入主密码确认）
- **完全离线**：云同步功能已停用，软件运行时不发起任何网络请求

## 下载与运行

从 [Releases](https://github.com/a756654285/PassVault/releases) 下载 `PassVault-v1.0.0-win64.zip`，**解压整个文件夹**后双击 `PassVault.exe`。

首次运行时 Windows 可能提示「Windows 已保护你的电脑」（未购买代码签名证书）：点「更多信息」→「仍要运行」。可先用 `SHA256SUMS.txt` 校验文件完整性：

```powershell
Get-FileHash .\PassVault-v1.0.0-win64.zip -Algorithm SHA256
```

首次输入的**主密码即创建保险库**，请务必牢记 —— 主密码不上传、不缓存、不可找回，开发者也无法解密你的数据。

## 数据在哪里

| 场景 | 位置 |
|---|---|
| 绿色版（默认） | 软件同目录 `数据库\autosave.vault` |
| 安装在无写权限目录 | `%APPDATA%\PassVault\数据库\autosave.vault` |

备份 = 复制整个 `数据库` 文件夹，或用「💽 数据库迁移」导出 `.vault`。**转发软件给别人时必须排除 `数据库` 文件夹**，里面是你的真实密码。升级软件直接替换程序文件即可，升级前先备份该文件夹。

更详细的使用说明见 [使用说明.txt](使用说明.txt)。

## 从源码运行 / 自行构建

需要 Node.js 16+：

```bash
npm install
npm start          # 开发模式运行
npm run pack       # 打包到 ./dist（electron-packager）
```

打 Release 包（会硬性拦截 `数据库` 文件夹与 `.vault` 文件，防止真实密码被打包）：

```bash
python scripts/build_release.py --version 1.0.0 --source <成品目录> --outdir <输出目录>
```

不带参数时默认读 `dist/PassVault-win32-x64`、输出到 `dist/release`。

目录结构：

```
main.js            Electron 主进程：窗口、本地文件读写、RDP/终端调用
preload.js         contextBridge 安全桥接
app/PassVault.html 单页界面 + 加解密逻辑（Web Crypto）
package.json       构建脚本
scripts/           Release 打包与校验脚本
```

## 安全说明

**设计上的保证**

- 密钥只在内存中，主密码不明文落盘；每条记录独立随机 IV，AES-GCM 认证加密
- 认证材料与加密密钥使用不同派生参数；服务端（已停用）即便存在也只拿到密文
- 无网络请求、无遥测、无第三方 SDK、无自动更新

**使用前请了解的局限**

- 主密码**不可找回、不提供重置**，遗忘即永久失去数据
- 无闲置自动锁定，离开电脑请手动点「🔒 锁定」
- 复制密码后剪贴板不会自动清空
- 「分享单条」导出的是**明文**文件，用完请及时删除
- 数据文件权限依赖所在目录的 Windows 权限，建议不要放在多人可读的共享目录
- **本项目未经独立第三方安全审计**，请自行评估是否用于高敏感场景

如发现安全问题，请通过 GitHub 私有安全通告（Security Advisories）报告，不要直接开公开 Issue。

## 隐私

本软件不收集、不存储、不传输任何个人信息或使用数据。没有账号体系，没有崩溃上报，没有统计埋点。所有数据仅保存在使用者本机的加密文件中。

## 许可证与免责

[MIT](LICENSE)。随发行包附带的 `LICENSE`（Electron，MIT）与 `LICENSES.chromium.html`（Chromium 及其组件许可）请一并保留。

本软件按「原样」提供，不附带任何明示或暗示的担保。使用者自行承担主密码保管与数据备份责任；因遗忘主密码、文件损坏或丢失造成的损失，作者不承担责任。
