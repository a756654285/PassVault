/* ============================================================
 * PassVault 增量更新模块（主进程）
 * ------------------------------------------------------------
 * 设计原则：
 *  1. 只从固定的 GitHub raw 地址读取一个 version.json 清单；
 *  2. 清单列出本次要更新的“程序文件”（相对程序根目录的路径 + SHA-256）；
 *  3. 下载到临时目录 → 逐个校验 SHA-256 → 全部通过后才替换；
 *  4. 白名单硬编码：只允许替换 main.js / preload.js / updater.js / app/PassVault.html / package.json；
 *     数据库目录、*.vault、sync.json、密钥相关文件一律不碰；
 *  5. 全程不接触任何密码/明文，不发起与更新无关的网络请求。
 * ============================================================ */
const { app, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');

// 更新清单地址（固定 GitHub raw，用户换仓库时改这里 + 重新打包一次即可）
const MANIFEST_URL = 'https://raw.githubusercontent.com/a756654285/PassVault/main/version.json';
const RELEASE_PAGE = 'https://github.com/a756654285/PassVault/releases';

// 允许被增量替换的文件白名单（相对程序根目录 app.getAppPath()）
const ALLOW = new Set(['main.js', 'preload.js', 'updater.js', 'app/PassVault.html', 'package.json']);

function appRoot() {
  try { return app.getAppPath(); }
  catch (e) { return path.dirname(process.execPath); }
}
function versionFile() { return path.join(appRoot(), 'package.json'); }

function currentVersion() {
  try { return String(JSON.parse(fs.readFileSync(versionFile(), 'utf8')).version || '').trim(); }
  catch (e) { return '0.0.0'; }
}
function cmpVer(a, b) {
  const A = String(a || '').split('.').map(x => parseInt(x, 10) || 0);
  const B = String(b || '').split('.').map(x => parseInt(x, 10) || 0);
  for (let i = 0; i < 4; i++) {
    const d = (A[i] || 0) - (B[i] || 0);
    if (d) return d > 0 ? 1 : -1;
  }
  return 0;
}
function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex').toLowerCase(); }
function safeRel(rel) {
  if (typeof rel !== 'string') return null;
  const r = rel.replace(/\\/g, '/').replace(/^\/+/, '');
  if (r.indexOf('..') >= 0) return null;          // 防目录穿越
  if (!ALLOW.has(r)) return null;                 // 白名单
  return r;
}
function tmpDir() {
  const d = path.join(app.getPath('userData'), 'pv-update-tmp');
  try { fs.mkdirSync(d, { recursive: true }); } catch (e) {}
  return d;
}

// 带超时的 HTTPS GET，返回 Buffer；跟随最多 3 次重定向
function httpsGet(url, redirects) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { return reject(new Error('地址无效')); }
    if (u.protocol !== 'https:') return reject(new Error('更新源必须使用 HTTPS'));
    const req = https.get(u, { headers: { 'User-Agent': 'PassVault-Updater', 'Cache-Control': 'no-cache' } }, res => {
      const code = res.statusCode || 0;
      if (code >= 300 && code < 400 && res.headers.location) {
        res.resume();
        if ((redirects || 0) >= 3) return reject(new Error('重定向过多'));
        return httpsGet(new URL(res.headers.location, u).href, (redirects || 0) + 1).then(resolve, reject);
      }
      if (code !== 200) { res.resume(); return reject(new Error('HTTP ' + code)); }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.setTimeout(20000, () => req.destroy(new Error('请求超时')));
    req.on('error', reject);
  });
}

// 检查更新：拉取 version.json，与本地版本比较（只读取，不改任何文件）
async function check() {
  try {
    const buf = await httpsGet(MANIFEST_URL + '?t=' + Date.now(), 0);
    const man = JSON.parse(buf.toString('utf8'));
    if (!man || !man.version || !Array.isArray(man.files)) throw new Error('清单格式不正确');
    const local = currentVersion();
    return {
      ok: true,
      hasUpdate: cmpVer(man.version, local) > 0,
      local, latest: man.version,
      date: man.date || '', notes: man.notes || '',
      count: man.files.length
    };
  } catch (e) {
    return { ok: false, msg: String(e && e.message || e) };
  }
}

// 下载 + 校验：把清单里的文件下载到临时目录，全部校验通过才落地缓存
async function download() {
  try {
    const buf = await httpsGet(MANIFEST_URL + '?t=' + Date.now(), 0);
    const man = JSON.parse(buf.toString('utf8'));
    if (!man || !man.version || !Array.isArray(man.files)) throw new Error('清单格式不正确');
    const base = String(man.baseUrl || '').replace(/\/+$/, '');
    if (!/^https:\/\//i.test(base)) throw new Error('文件源必须使用 HTTPS');
    const dir = tmpDir();
    // 清空临时目录里的旧 .dl 文件
    try { for (const f of fs.readdirSync(dir)) if (/\.dl$/.test(f)) fs.unlinkSync(path.join(dir, f)); } catch (e) {}

    for (let i = 0; i < man.files.length; i++) {
      const it = man.files[i];
      const rel = safeRel(it && it.path);
      if (!rel) throw new Error('清单含不允许的文件：' + String(it && it.path));
      const fileUrl = base + '/' + rel.split('/').map(encodeURIComponent).join('/') + '?t=' + Date.now();
      const data = await httpsGet(fileUrl, 0);
      if (it.sha256 && sha256(data) !== String(it.sha256).toLowerCase()) {
        throw new Error('校验失败：' + rel + '（文件可能被篡改或下载不完整）');
      }
      const dest = path.join(dir, rel.replace(/\//g, '__') + '.dl');
      fs.writeFileSync(dest, data);
    }
    // 缓存清单，供 apply 使用
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(man));
    return { ok: true, version: man.version, count: man.files.length };
  } catch (e) {
    return { ok: false, msg: String(e && e.message || e) };
  }
}

// 应用更新：从临时目录把已校验的文件替换到程序目录（仅白名单）
function apply() {
  try {
    const dir = tmpDir();
    const man = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
    const root = appRoot();
    for (const it of man.files) {
      const rel = safeRel(it && it.path);
      if (!rel) throw new Error('清单含不允许的文件');
      const src = path.join(dir, rel.replace(/\//g, '__') + '.dl');
      if (!fs.existsSync(src)) throw new Error('缺少已下载文件：' + rel);
      const data = fs.readFileSync(src);
      if (it.sha256 && sha256(data) !== String(it.sha256).toLowerCase()) throw new Error('替换前校验失败：' + rel);
      const dest = path.join(root, rel);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      // 先写 .new 再 rename，降低写一半的风险
      const tmp = dest + '.new';
      fs.writeFileSync(tmp, data);
      fs.renameSync(tmp, dest);
    }
    try { for (const f of fs.readdirSync(dir)) fs.unlinkSync(path.join(dir, f)); } catch (e) {}
    return { ok: true, msg: '更新已应用，请关闭并重新打开软件生效' };
  } catch (e) {
    return { ok: false, msg: String(e && e.message || e) };
  }
}

function register() {
  ipcMain.handle('update-check', async () => check());
  ipcMain.handle('update-download', async () => download());
  ipcMain.handle('update-apply', async () => apply());
  ipcMain.handle('update-info', async () => ({
    version: currentVersion(), releasePage: RELEASE_PAGE, manifestUrl: MANIFEST_URL
  }));
}

module.exports = { register, currentVersion };
