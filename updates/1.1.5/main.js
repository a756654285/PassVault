// PassVault 桌面壳：把本地 PassVault.html 作为单页应用加载，免安装、离线、本地
const { app, BrowserWindow, ipcMain, shell, Menu, Tray } = require('electron');
const path = require('path');
const fs = require('fs');
const cp = require('child_process');

// 软件内增量更新（检查/下载/校验/替换，白名单保护，不接触任何密码数据）
const updater = require('./updater.js');
updater.register();

/* 数据目录：绿色版优先放软件同级的「数据库」文件夹，便于备份/迁移；
   装到 Program Files 等无写权限位置时自动回退到 %APPDATA%\PassVault\数据库。
   不写死任何盘符、用户名或机器专属路径。*/
function appBaseDir(){
  return app.isPackaged ? path.dirname(app.getPath('exe')) : app.getAppPath();
}
function configDir(){
  const cands = [
    path.join(appBaseDir(), '数据库'),
    path.join(app.getPath('userData'), '数据库')
  ];
  for (const d of cands) {
    try { fs.mkdirSync(d, { recursive:true }); fs.accessSync(d, fs.constants.W_OK); return d; }
    catch (e) {}
  }
  return app.getPath('userData');
}
// 兼容早期版本：若程序目录上一层存在旧「数据库」文件夹且新目录无数据，则复制过来（只复制，绝不删原件）
function migrateLegacyData(){
  try {
    const legacy = path.resolve(appBaseDir(), '..', '数据库');
    const target = configDir();
    if (path.resolve(legacy) === path.resolve(target)) return;
    for (const f of ['autosave.vault', 'sync.json']) {
      const from = path.join(legacy, f), to = path.join(target, f);
      if (fs.existsSync(from) && !fs.existsSync(to)) fs.copyFileSync(from, to);
    }
  } catch (e) {}
}

// 云同步：读取同步配置（仅用于"忽略自签证书"开关），路径与数据库统一
{ try {
  const _c = JSON.parse(fs.readFileSync(path.join(configDir(), 'sync.json'), 'utf8'));
  if (_c && _c.insecure) app.commandLine.appendSwitch('ignore-certificate-errors');
} catch (e) {} }

// 跳转：http/https 交给系统默认浏览器；\\ 开头的共享文件夹路径交给 Windows 资源管理器
ipcMain.handle('open-external', async (e, url) => {
  try {
    const u = String(url || '').trim();
    if (/^https?:\/\//i.test(u)) { await shell.openExternal(u); return true; }
    if (/^\\\\.+/.test(u)) { const err = await shell.openPath(u); return !err; }   // UNC 共享路径
    return false;
  } catch (err) { return false; }
});

/* ================= 远程连接：Windows 远程桌面（mstsc / RDP）=================
 * 机制：生成一个临时 .rdp 文件，再用 cmdkey 把账号密码预置到 Windows 凭据管理器
 * （目标 TERMSRV/<地址>），mstsc 启动时即可免手工输入密码直接登录。
 * mstsc 退出后自动删除临时文件与预置凭据；cmdkey 不可用时退化为把密码写进
 * 临时 .rdp（退出即删），保证仍能自动登录。
 */
const MSTSC  = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'mstsc.exe');
const CMDKEY = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'cmdkey.exe');

function execFileP(file, args) {
  return new Promise(resolve => {
    cp.execFile(file, args, { windowsHide: true }, (err) => {
      resolve({ ok: !err, err: err ? String(err.message || err) : '' });
    });
  });
}
// RDP 文件里的密码是 UTF-16LE 十六进制
function rdpPasswordHex(pw) { return Buffer.from(String(pw || ''), 'utf16le').toString('hex').toUpperCase(); }
// 解析 主机:端口（RDP 默认 3389，端口为默认值时 full 只留主机）
function splitHostPort(host) {
  let h = String(host || '').trim(), port = '3389';
  const m = h.match(/^(.+?):(\d{1,5})$/);
  if (m) { h = m[1]; port = m[2]; }
  return { host: h, port, full: (port === '3389') ? h : (h + ':' + port) };
}
function buildRdpText(full, user, domain, pwHex) {
  const L = [
    'screen mode id:i:2', 'use multimon:i:0', 'desktopwidth:i:1920', 'desktopheight:i:1080',
    'session bpp:i:32', 'full address:s:' + full, 'compression:i:1', 'keyboardhook:i:2',
    'audiocapturemode:i:0', 'videoplaybackmode:i:1', 'connection type:i:7',
    'networkautodetect:i:1', 'bandwidthautodetect:i:1', 'displayconnectionbar:i:1',
    'disable wallpaper:i:0', 'allow font smoothing:i:1', 'allow desktop composition:i:1',
    'disable full window drag:i:0', 'disable menu anims:i:0', 'disable themes:i:0',
    'disable cursor setting:i:0', 'bitmapcachepersistenable:i:1',
    'redirectclipboard:i:1', 'redirectprinters:i:0', 'redirectcomports:i:0',
    'redirectsmartcards:i:0', 'autoreconnection enabled:i:1',
    'authentication level:i:0', 'prompt for credentials:i:0',
    'negotiate security layer:i:1', 'remoteapplicationmode:i:0',
    'alternate shell:s:', 'shell working directory:s:',
    'gatewayusagemethod:i:4', 'gatewaycredentialssource:i:4',
    'gatewayprofileusagemethod:i:0', 'promptcredentialonce:i:0',
    'use redirection server name:i:0'
  ];
  if (user) L.push('username:s:' + (domain ? (domain + '\\' + user) : user));
  if (pwHex) L.push('password 51:b:' + pwHex);
  return '\ufeff' + L.join('\r\n') + '\r\n';
}

ipcMain.handle('launch-rdp', async (e, opt) => {
  const hostRaw = String((opt && opt.host) || '').trim();
  const user    = String((opt && opt.username) || '').trim();
  const pass    = String((opt && opt.password) || '');
  const domain  = String((opt && opt.domain) || '').trim();
  if (!hostRaw) return { ok: false, error: '未填写主机地址' };
  const { full } = splitHostPort(hostRaw);
  const tmp = path.join(app.getPath('temp'),
    'passvault_rdp_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7) + '.rdp');
  const credTarget = 'TERMSRV/' + full;
  let stashed = false, done = false;
  const finish = () => {
    if (done) return; done = true;
    try { fs.unlinkSync(tmp); } catch (_) {}
    if (stashed) execFileP(CMDKEY, ['/delete:' + credTarget]);
  };
  try {
    fs.writeFileSync(tmp, buildRdpText(full, user, domain, ''), 'utf8');
    if (user) {
      const r = await execFileP(CMDKEY,
        ['/generic:' + credTarget, '/user:' + (domain ? (domain + '\\' + user) : user), '/pass:' + pass]);
      stashed = r.ok;
      if (!stashed) {   // cmdkey 失败：把密码写进临时 rdp，仍可自动登录
        fs.writeFileSync(tmp, buildRdpText(full, user, domain, rdpPasswordHex(pass)), 'utf8');
      }
    }
    const child = cp.spawn(MSTSC, [tmp], { stdio: 'ignore' });
    child.on('error', finish);
    child.on('exit', finish);
    setTimeout(() => { try { fs.unlinkSync(tmp); } catch (_) {} }, 600000);  // 兜底清临时文件
    return { ok: true, stashed };
  } catch (err) {
    finish();
    return { ok: false, error: String((err && err.message) || err) };
  }
});

/* ================= 远程连接：SSH 终端 =================
 * SSH 协议无法从命令行传入密码（安全限制），因此这里只负责把 ssh 命令
 * 写进一个新开的终端窗口，用户在该窗口里手动输入密码。
 */
ipcMain.handle('open-terminal', (e, cmd) => {
  try {
    const c = String(cmd || '').trim();
    if (!c) return { ok: false, error: '空命令' };
    // 直接拉起可见控制台窗口（GUI 进程下 detached 子进程自带新控制台，无需 start）
    const child = cp.spawn('cmd.exe', ['/k', c],
      { detached: true, stdio: 'ignore', windowsHide: false });
    child.unref();
    return { ok: true };
  } catch (err) { return { ok: false, error: String((err && err.message) || err) }; }
});

/* ================= 远程连接：交换机 / 网络设备终端（CRT 式）=================
 * 点击条目「远程」按钮 → 优先调用 SecureCRT（如已安装）直接跳转到目标设备会话；
 * 否则回退到 Windows Terminal / 系统 ssh·telnet 打开终端窗口，供手动操作。
 * 说明：SSH/Telnet 协议不允许在命令行传入密码（安全限制），
 *       故由用户在终端里手动输入密码——与 SecureCRT 行为一致。
 */
const SECURECRT_CANDIDATES = [
  'SecureCRT.exe',
  'C:\\Program Files\\VanDyke Software\\SecureCRT\\SecureCRT.exe',
  'C:\\Program Files (x86)\\VanDyke Software\\SecureCRT\\SecureCRT.exe',
  'D:\\Program Files\\VanDyke Software\\SecureCRT\\SecureCRT.exe',
  'C:\\Program Files\\VanDyke Software\\Clients\\SecureCRT.exe'
];
function findSecureCRT(){
  for (const c of SECURECRT_CANDIDATES) {
    try { if (fs.existsSync(c)) return c; } catch (e) {}
  }
  try {
    const p = cp.execSync('where SecureCRT.exe', { windowsHide: true }).toString().trim().split(/\r?\n/)[0];
    if (p && fs.existsSync(p)) return p;
  } catch (e) {}
  return '';
}
function splitHostPort2(host, defPort){
  let h = String(host || '').trim(), port = String(defPort);
  const m = h.match(/^(.+?):(\d{1,5})$/); if (m) { h = m[1]; port = m[2]; }
  return { host: h, port };
}
ipcMain.handle('launch-term', (e, opt) => {
  try {
    const proto = String((opt && opt.proto) || 'ssh').toLowerCase();
    const hostRaw = String((opt && opt.host) || '').trim();
    const user = String((opt && opt.username) || '').trim();
    if (!hostRaw) return { ok: false, error: '未填写主机地址' };
    const defPort = proto === 'telnet' ? '23' : '22';
    const { host, port } = splitHostPort2(hostRaw, defPort);
    const crt = findSecureCRT();
    if (crt) {
      const args = [];
      if (proto === 'telnet') args.push('/TELNET'); else args.push('/SSH2');
      if (port && port !== defPort) args.push('/P', port);
      if (user) args.push('/L', user);
      args.push(host);
      const child = cp.spawn(crt, args, { detached: true, stdio: 'ignore', windowsHide: false });
      child.unref();
      return { ok: true, method: 'securecrt' };
    }
    // 回退 1：Windows Terminal
    let isWT = false;
    try { cp.execSync('where wt.exe', { windowsHide: true }); isWT = true; } catch (e) {}
    const cmd = proto === 'telnet'
      ? ('telnet ' + host + (port !== '23' ? ' ' + port : ''))
      : ('ssh ' + (user ? user + '@' : '') + host + (port !== '22' ? ' -p ' + port : ''));
    if (isWT) {
      const child = cp.spawn('wt.exe', ['cmd', '/k', cmd], { detached: true, stdio: 'ignore', windowsHide: false });
      child.unref();
      return { ok: true, method: 'wt' };
    }
    // 回退 2：cmd /k（系统自带 ssh/telnet）
    const child = cp.spawn('cmd.exe', ['/k', cmd],
      { detached: true, stdio: 'ignore', windowsHide: false });
    child.unref();
    return { ok: true, method: 'cmd' };
  } catch (err) { return { ok: false, error: String((err && err.message) || err) }; }
});

// 自动保存：加密保险库写到 configDir() 决定的目录，关掉再开自动恢复
function autosaveDir(){ return configDir(); }
function autosavePath() { return path.join(autosaveDir(), 'autosave.vault'); }
ipcMain.handle('autosave-write', (e, text) => { try { fs.writeFileSync(autosavePath(), text); } catch (e) {} });
ipcMain.handle('autosave-read', () => { try { return fs.readFileSync(autosavePath(), 'utf8'); } catch (e) { return null; } });
ipcMain.handle('autosave-clear', () => { try { fs.unlinkSync(autosavePath()); } catch (e) {} });

// 云同步配置（服务器地址 / 用户名 / token / 版本 / 忽略证书）本地持久化
function syncConfigPath() { return path.join(autosaveDir(), 'sync.json'); }
function readSyncConfig() { try { return JSON.parse(fs.readFileSync(syncConfigPath(), 'utf8')); } catch (e) { return {}; } }
function writeSyncConfig(obj) { try { fs.writeFileSync(syncConfigPath(), JSON.stringify(obj, null, 2)); } catch (e) {} }
ipcMain.handle('sync-config-read', () => readSyncConfig());
ipcMain.handle('sync-config-write', (e, obj) => { writeSyncConfig(obj); return true; });

// 内置默认同步服务器：开发者将 {"server":"http(s)://地址:端口"} 写入软件目录的
// sync.default.json，最终用户打开即可直接连接，无需手动填写服务器地址。
function defaultSyncServer(){
  for (const base of [__dirname, path.dirname(app.getPath('exe'))]) {
    try {
      const p = path.join(base, 'sync.default.json');
      if (fs.existsSync(p)) { const j = JSON.parse(fs.readFileSync(p, 'utf8')); if (j && j.server) return j.server; }
    } catch (e) {}
  }
  return '';
}
ipcMain.handle('get-default-sync', () => ({ server: defaultSyncServer() }));

/* ================= 自动登录：受控窗口内填入账号密码 =================
 * 安全边界：
 *  - 凭据只由渲染进程经 IPC 传入主进程内存，不写文件/日志/剪贴板，不拼进 URL；
 *  - 登录窗口 nodeIntegration=false、contextIsolation=true、sandbox=true，
 *    并使用独立内存会话，与目标网站和保险库主窗口彻底隔离；
 *  - 只填不点"登录"，最后一步由用户本人确认，避免误提交。
 */
function buildAutofillScript(user, pass) {
  const u = JSON.stringify(String(user || ''));
  const p = JSON.stringify(String(pass || ''));
  return `(function(){
    function visible(el){ try{ var s=getComputedStyle(el);
      return s.display!=='none' && s.visibility!=='hidden' && el.getClientRects().length>0; }catch(e){ return true; } }
    function setValue(el, v){
      if(!el) return false;
      try{
        var proto = el.tagName==='TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        var setter = Object.getOwnPropertyDescriptor(proto,'value');
        if(setter && setter.set) setter.set.call(el, v); else el.value = v;
      }catch(e){ el.value = v; }
      try{
        el.dispatchEvent(new Event('input',{bubbles:true}));
        el.dispatchEvent(new Event('change',{bubbles:true}));
      }catch(e){}
      return true;
    }
    var pwList = Array.prototype.slice.call(document.querySelectorAll('input[type=password]')).filter(visible);
    if(!pwList.length) return {ok:false, reason:'no-password-field'};
    var pw = pwList[0];
    if(pw.value && pw.value.length) return {ok:true, reason:'already-filled'};
    var scope = pw.form || document;
    var all = Array.prototype.slice.call(scope.querySelectorAll('input')).filter(visible).filter(function(x){
      return x!==pw && x.type!=='password' && x.type!=='hidden' && x.type!=='submit' &&
             x.type!=='button' && x.type!=='checkbox' && x.type!=='radio';
    });
    var nameRe = /user|account|login|email|mail|phone|tel|username|zhanghao/i;
    var acc = all.filter(function(x){ return nameRe.test([x.name,x.id,x.placeholder,x.autocomplete].join(' ')); })[0];
    if(!acc) acc = all.filter(function(x){ return /^(text|email|tel)$/.test(x.type); })[0];
    if(!acc) acc = all[0];
    var filledUser = acc ? setValue(acc, ${u}) : false;
    var filledPass = setValue(pw, ${p});
    return {ok:filledPass, filledUser:filledUser};
  })()`;
}

ipcMain.handle('autofill-login', async (e, opt) => {
  let url = '', user = '', pass = '';
  try {
    url  = String((opt && opt.url) || '').trim();
    user = String((opt && opt.username) || '');
    pass = String((opt && opt.password) || '');
  } catch (err) {}
  if (!/^https?:\/\//i.test(url)) return { ok:false, msg:'仅支持 http/https 网址' };
  if (!pass) return { ok:false, msg:'该条目没有密码，无法自动填充' };

  try {
    const win = new BrowserWindow({
      width: 1080, height: 780,
      title: 'PassVault 自动登录 · 正在填入',
      backgroundColor: '#ffffff',
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        webSecurity: true,
        partition: 'pv-autologin-temp'   // 非 persist: → 内存会话，关闭即清空 Cookie
      }
    });
    win.removeMenu();

    let round = 0;
    const fillFrame = async (frame) => {
      if (!frame || win.isDestroyed()) return;
      try {
        const r = await frame.executeJavaScript(buildAutofillScript(user, pass));
        if (r && r.ok) win.setTitle('PassVault 自动登录 · 已填入（请自行确认登录）');
      } catch (err) {}
    };
    const fillAll = async () => {
      if (win.isDestroyed()) return;
      try {
        const root = win.webContents.mainFrame;
        const frames = (root && root.framesInSubtree) ? root.framesInSubtree : [root];
        for (const f of frames) await fillFrame(f);
      } catch (err) { await fillFrame(win.webContents.mainFrame); }
    };
    win.webContents.on('did-finish-load', () => {
      round = 0;
      setTimeout(async () => {
        const doRound = async () => {
          if (win.isDestroyed()) return;
          await fillAll();
          round++;
          if (round < 4) setTimeout(doRound, 900);   // 兼容 SPA/延迟渲染的登录页
        };
        doRound();
      }, 400);
    });
    // 伪装 UA 为新版 Chrome：部分网银/企业登录页检测 Electron 标识会拒绝加载并提示"浏览器版本过低"
    try {
      win.webContents.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
    } catch (err) {}
    win.loadURL(url);
    return { ok:true };
  } catch (err) {
    return { ok:false, msg:'打开登录窗口失败：' + String((err && err.message) || err) };
  }
});

/* ================= 关闭行为：点右上角 X 时询问「最小化到托盘」还是「退出」=================
 * isQuitting 标记真退出，避免退出时再被 close 拦截形成死循环。
 * 最小化到托盘后：单击/双击托盘图标恢复窗口，右键菜单可显示或退出。
 */
let isQuitting = false;
let tray = null;

function createTray(win) {
  if (tray) return tray;
  const icon = path.join(__dirname, 'tray.ico');
  tray = new Tray(fs.existsSync(icon) ? icon : path.join(__dirname, 'app', 'tray.ico'));
  tray.setToolTip('PassVault · 密码保险库');
  const show = () => { if (win && !win.isDestroyed()) { win.show(); win.focus(); } };
  const quit = () => { isQuitting = true; app.quit(); };
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: '显示主窗口', click: show },
    { type: 'separator' },
    { label: '退出 PassVault', click: quit }
  ]));
  tray.on('click', show);        // 单击托盘图标恢复窗口
  tray.on('double-click', show); // 双击也恢复
  return tray;
}

function handleWindowClose(win, e) {
  if (isQuitting) return;        // 真退出流程，不拦截
  e.preventDefault();            // 拦住默认关闭
  // 让页面弹出主题化的关闭确认框（与软件深色风格一致）
  try { win.webContents.send('close-ask'); }
  catch (err) { isQuitting = true; app.quit(); }  // 页面未就绪时的兜底：直接退出
}

// 用户在主题弹窗里做出选择后回传：0 最小化到托盘 / 1 退出 / 2 取消
ipcMain.handle('close-choice', (e, choice) => {
  const win = BrowserWindow.fromWebContents(e.sender);
  if (choice === 0) { if (win) { createTray(win); win.hide(); } }
  else if (choice === 1) { isQuitting = true; app.quit(); }
  // choice === 2 取消：页面自己关掉弹窗即可，窗口保持打开
  return true;
});

function createWindow() {
  const win = new BrowserWindow({
    width: 1180,
    height: 820,
    minWidth: 860,
    minHeight: 600,
    title: 'PassVault · 密码保险库',
    backgroundColor: '#0a0e0a',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  // 隐藏菜单栏（保持简洁黑客风）
  win.removeMenu();

  // 加载本地页面（asar 内 / 文件内均可，file:// 视为 secure context，Web Crypto 正常）
  win.loadFile(path.join(__dirname, 'app', 'PassVault.html'));

  // 只允许本地导航，杜绝任何外链跳走
  win.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) event.preventDefault();
  });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  // 让下载（导出保险库 / 分享文件）落到原生下载目录
  win.webContents.session.on('will-download', (event, item) => {
    const fallback = path.join(app.getPath('downloads'), item.getFilename());
    if (!item.getFilename()) item.setSavePath(fallback);
  });

  // 点右上角 X：询问最小化到托盘 / 退出软件
  win.on('close', (e) => handleWindowClose(win, e));

  // 托盘图标随主窗口创建，点右下角图标即可恢复
  createTray(win);
}

app.whenReady().then(() => {
  migrateLegacyData();   // 旧路径数据一次性搬迁（只复制，不删原件）
  createWindow();
  app.on('activate', () => {
    const wins = BrowserWindow.getAllWindows();
    if (wins.length) { wins[0].show(); wins[0].focus(); }
    else createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// 真正退出时销毁托盘图标，避免系统托盘残留
app.on('before-quit', () => {
  isQuitting = true;
  if (tray) { try { tray.destroy(); } catch (e) {} tray = null; }
});
