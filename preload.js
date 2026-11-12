// 预加载脚本：在隔离环境里向页面安全暴露原生剪贴板能力
const { contextBridge, clipboard, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('__pv', {
  // 复制文本到系统剪贴板（Electron 原生，file:// 下最稳）
  copy: (text) => {
    try { clipboard.writeText(text == null ? '' : String(text)); return true; }
    catch (e) { return false; }
  },
  // 读取系统剪贴板
  paste: () => {
    try { return clipboard.readText(); } catch (e) { return ''; }
  },
  // 加密自动备份：把保险库明文 JSON 交给主进程写入 userData/autosave.vault
  writeAutoSave: (text) => ipcRenderer.invoke('autosave-write', text),
  // 读取自动备份（无则返回 null）
  readAutoSave: () => ipcRenderer.invoke('autosave-read'),
  // 清除自动备份
  clearAutoSave: () => ipcRenderer.invoke('autosave-clear'),
  // 用系统默认浏览器打开网址（URL 由主进程校验：仅允许 http/https）
  openExternal: (url) => ipcRenderer.invoke('open-external', url),
  // 启动 Windows 远程桌面（mstsc）连接，自动填充账号密码
  launchRdp: (opt) => ipcRenderer.invoke('launch-rdp', opt),
  // 打开一个新终端窗口执行给定命令（用于 SSH 等远程连接）
  openTerminal: (cmd) => ipcRenderer.invoke('open-terminal', cmd),
  // 启动交换机 / 网络设备终端（优先 SecureCRT，回退 Windows Terminal / ssh·telnet）
  launchTerm: (opt) => ipcRenderer.invoke('launch-term', opt),
  // 云同步配置读写（服务器地址/用户名/token/版本/忽略证书，存于本地，不含主密码）
  readSyncConfig: () => ipcRenderer.invoke('sync-config-read'),
  writeSyncConfig: (obj) => ipcRenderer.invoke('sync-config-write', obj),
  // 读取软件内置的默认同步服务器地址（开发者配置，最终用户无需填写）
  getDefaultSync: () => ipcRenderer.invoke('get-default-sync')
});
