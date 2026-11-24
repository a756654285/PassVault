/* ============================================================
 * PassVault 增量更新模块（主进程）—— 多源 + 数字签名版
 * ------------------------------------------------------------
 * 设计原则：
 *  1. 清单 version.json 从 3 个源依次尝试：GitHub Raw → jsDelivr CDN → GitHub API；
 *  2. 每个源的清单必须先通过内置 Ed25519 公钥验签（version.sig），
 *     验签失败即判定该源被篡改并自动切下一个源；全部失败则拒绝更新；
 *  3. 清单列出要更新的程序文件（相对路径 + SHA-256），文件本体也从多源尝试下载；
 *  4. 下载到临时目录 → 逐个校验 SHA-256 → 全部通过后才替换；
 *  5. 白名单硬编码：只允许替换 main.js / preload.js / updater.js / app/PassVault.html / package.json；
 *     数据库目录、*.vault、sync.json、密钥相关文件一律不碰；
 *  6. 全程不接触任何密码/明文，不发起与更新无关的网络请求。
 *
 * 兼容性：version.json 保留 baseUrl 字段，已安装 1.1.4 的旧版客户端可正常读取；
 *         新增的 baseUrls / 签名对旧版无影响。
 * ============================================================ */
const { app, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');

// 内置公钥（DER-SPKI 的 BASE64，可公开；对应私钥只在发布者本机）
const PUB_KEY_B64 = 'MCowBQYDK2VwAyEAD+wzuQjgnR5fyTLsfs4Q/+bUcljehD94PhAyx0hdCBQ=';

const REPO_OWNER = 'a756654285';
const REPO_NAME = 'PassVault';
const BRANCH = 'main';
const RELEASE_PAGE = 'https://github.com/a756654285/PassVault/releases';

// 允许被增量替换的文件白名单（相对程序根目录 app.getAppPath()）
const ALLOW = new Set(['main.js', 'preload.js', 'updater.js', 'app/PassVault.html', 'package.json']);

let _publicKey = null;
function publicKey() {
  if (!_publicKey) {
    _publicKey = crypto.createPublicKey({
      key: Buffer.from(PUB_KEY_B64, 'base64'),
      format: 'der',
      type: 'spki'
    });
  }
  return _publicKey;
}

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

// 带超时的 HTTPS GET，返回 Buffer；跟随最多 3 次重定向；单源超时 8 秒
function httpsGet(url, redirects, extraHeaders) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { return reject(new Error('地址无效')); }
    if (u.protocol !== 'https:') return reject(new Error('更新源必须使用 HTTPS'));
    const headers = Object.assign(
      { 'User-Agent': 'PassVault-Updater', 'Cache-Control': 'no-cache' },
      extraHeaders || {}
    );
    const req = https.get(u, { headers }, res => {
      const code = res.statusCode || 0;
      if (code >= 300 && code < 400 && res.headers.location) {
        res.resume();
        if ((redirects || 0) >= 3) return reject(new Error('重定向过多'));
        return httpsGet(new URL(res.headers.location, u).href, (redirects || 0) + 1, extraHeaders).then(resolve, reject);
      }
      if (code !== 200) { res.resume(); return reject(new Error('HTTP ' + code)); }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.setTimeout(8000, () => req.destroy(new Error('请求超时')));
    req.on('error', reject);
  });
}

// ---- 清单三源：每个源都要同时拿到 version.json 和 version.sig，且验签通过 ----
const MANIFEST_SOURCES = [
  {
    name: 'GitHub Raw',
    get(file) {
      return httpsGet('https://raw.githubusercontent.com/' + REPO_OWNER + '/' + REPO_NAME + '/' + BRANCH + '/' + file + '?t=' + Date.now(), 0);
    }
  },
  {
    name: 'jsDelivr CDN',
    get(file) {
      return httpsGet('https://cdn.jsdelivr.net/gh/' + REPO_OWNER + '/' + REPO_NAME + '@' + BRANCH + '/' + file + '?t=' + Date.now(), 0);
    }
  },
  {
    name: 'GitHub API',
    get(file) {
      return httpsGet(
        'https://api.github.com/repos/' + REPO_OWNER + '/' + REPO_NAME + '/contents/' + file + '?t=' + Date.now(),
        0,
        { 'Accept': 'application/vnd.github+json' }
      ).then(buf => {
        let o;
        try { o = JSON.parse(buf.toString('utf8')); } catch (e) { throw new Error('API 返回格式异常'); }
        if (!o || typeof o.content !== 'string' || o.encoding !== 'base64') throw new Error('API 内容字段异常');
        return Buffer.from(o.content, 'base64');
      });
    }
  }
];

// 依次尝试各源，返回首个「验签通过 + 格式正确」的清单
async function fetchSignedManifest() {
  const errors = [];
  for (const src of MANIFEST_SOURCES) {
    try {
      const manBuf = await src.get('version.json');
      const sigBuf = await src.get('version.sig');
      const sigText = sigBuf.toString('utf8').trim();
      const sig = Buffer.from(sigText, 'base64');
      if (!sig.length || !crypto.verify(null, manBuf, publicKey(), sig)) {
        throw new Error('签名校验失败（清单可能被篡改）');
      }
      const man = JSON.parse(manBuf.toString('utf8'));
      if (!man || !man.version || !Array.isArray(man.files)) throw new Error('清单格式不正确');
      return { man, source: src.name };
    } catch (e) {
      errors.push(src.name + ': ' + String(e && e.message || e));
    }
  }
  throw new Error('所有更新源均不可用或未通过验签\n' + errors.join('\n'));
}

// 文件下载候选地址：优先用清单里的 baseUrls，其次兼容旧版 baseUrl，最后按版本号兜底
function fileBases(man) {
  const urls = [];
  if (Array.isArray(man.baseUrls)) {
    for (const b of man.baseUrls) urls.push(String(b).replace(/\/+$/, ''));
  }
  if (man.baseUrl) urls.push(String(man.baseUrl).replace(/\/+$/, ''));
  urls.push('https://raw.githubusercontent.com/' + REPO_OWNER + '/' + REPO_NAME + '/' + BRANCH + '/updates/' + man.version);
  urls.push('https://cdn.jsdelivr.net/gh/' + REPO_OWNER + '/' + REPO_NAME + '@' + BRANCH + '/updates/' + man.version);
  urls.push('https://api.github.com/repos/' + REPO_OWNER + '/' + REPO_NAME + '/contents/updates/' + man.version);
  return Array.from(new Set(urls)).filter(u => /^https:\/\//i.test(u));
}

// 对单个文件的所有候选地址逐个尝试；SHA 不匹配视为该源不可信，继续下一源
async function downloadVerified(bases, rel, expectedSha) {
  const encoded = rel.split('/').map(encodeURIComponent).join('/');
  const errors = [];
  for (const base of bases) {
    try {
      let data;
      if (/^https:\/\/api\.github\.com\//i.test(base)) {
        const buf = await httpsGet(base + '/' + encoded + '?t=' + Date.now(), 0, { 'Accept': 'application/vnd.github+json' });
        let o;
        try { o = JSON.parse(buf.toString('utf8')); } catch (e) { throw new Error('API 返回格式异常'); }
        if (!o || typeof o.content !== 'string' || o.encoding !== 'base64') throw new Error('API 内容字段异常');
        data = Buffer.from(o.content, 'base64');
      } else {
        data = await httpsGet(base + '/' + encoded + '?t=' + Date.now(), 0);
      }
      if (expectedSha && sha256(data) !== String(expectedSha).toLowerCase()) {
        throw new Error('SHA-256 不匹配');
      }
      return data;
    } catch (e) {
      errors.push(base.replace(/^https:\/\//, '').slice(0, 48) + ': ' + String(e && e.message || e));
    }
  }
  throw new Error('文件下载失败（所有源）: ' + rel + '\n' + errors.join('\n'));
}

// 检查更新：拉取并验签 version.json，与本地版本比较（只读取，不改任何文件）
async function check() {
  try {
    const { man, source } = await fetchSignedManifest();
    const local = currentVersion();
    return {
      ok: true,
      hasUpdate: cmpVer(man.version, local) > 0,
      local, latest: man.version,
      date: man.date || '', notes: man.notes || '',
      count: man.files.length,
      source
    };
  } catch (e) {
    return { ok: false, msg: String(e && e.message || e) };
  }
}

// 下载 + 校验：把清单里的文件下载到临时目录，全部校验通过才落地缓存
async function download() {
  try {
    const { man, source } = await fetchSignedManifest();
    const bases = fileBases(man);
    if (!bases.length) throw new Error('清单未提供可用的文件源');
    const dir = tmpDir();
    // 清空临时目录里的旧 .dl 文件
    try { for (const f of fs.readdirSync(dir)) if (/\.dl$/.test(f)) fs.unlinkSync(path.join(dir, f)); } catch (e) {}

    for (let i = 0; i < man.files.length; i++) {
      const it = man.files[i];
      const rel = safeRel(it && it.path);
      if (!rel) throw new Error('清单含不允许的文件：' + String(it && it.path));
      const data = await downloadVerified(bases, rel, it.sha256);
      const dest = path.join(dir, rel.replace(/\//g, '__') + '.dl');
      fs.writeFileSync(dest, data);
    }
    // 缓存清单，供 apply 使用
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(man));
    return { ok: true, version: man.version, count: man.files.length, source };
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
    version: currentVersion(),
    releasePage: RELEASE_PAGE,
    sources: MANIFEST_SOURCES.map(s => s.name)
  }));
}

module.exports = { register, currentVersion };
