# -*- coding: utf-8 -*-
"""PassVault Release 打包脚本（防误打包真实密码）

用法：
    python scripts/build_release.py
    python scripts/build_release.py --version 1.0.1 --source <成品目录>

做三件事：
  1. 硬性拦截：任何 数据库/、*.vault、autosave.vault、sync.json 都不允许进包
  2. 把绿色版程序打成 zip（保留顶层文件夹名，解压即用）
  3. 计算 SHA256 并写 SHA256SUMS.txt

发布前请确认成品目录里的 main.js / app/PassVault.html 与源码一致。
"""
import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

# 默认路径全部相对仓库推导，不写死任何盘符或用户名
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = REPO_ROOT / "dist" / "PassVault-win32-x64"   # npm run pack 的产物
DEFAULT_OUTDIR = REPO_ROOT / "dist" / "release"                 # 已被 .gitignore 忽略

# 目录名/文件名命中即排除（大小写不敏感）
EXCLUDE_DIRS = {"数据库", "node_modules", ".git", "__pycache__"}
EXCLUDE_NAMES = {"thumbs.db", ".ds_store"}
EXCLUDE_SUFFIX = (".vault", ".log", ".tmp")
# 命中即视为致命错误（说明有真实数据混进来了）
FORBIDDEN_PARTS = ("数据库", "autosave.vault", "sync.json")


def is_forbidden(rel: Path) -> bool:
    low = str(rel).replace("\\", "/").lower()
    return any(p.lower() in low for p in FORBIDDEN_PARTS) or low.endswith(".vault")


def collect(source: Path):
    files, skipped = [], []
    for p in sorted(source.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(source)
        parts = {x.lower() for x in rel.parts}
        name = p.name.lower()
        if parts & {d.lower() for d in EXCLUDE_DIRS} or name in EXCLUDE_NAMES or name.endswith(EXCLUDE_SUFFIX):
            skipped.append(str(rel))
            continue
        if is_forbidden(rel):
            print(f"[致命] 检测到私有数据文件，拒绝打包: {rel}", file=sys.stderr)
            sys.exit(2)
        files.append((p, rel))
    return files, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    ap.add_argument("--outdir", type=Path, default=DEFAULT_OUTDIR)
    a = ap.parse_args()

    source = a.source.resolve()
    outdir = a.outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    if not (source / "PassVault.exe").exists():
        print(f"[致命] 未找到 PassVault.exe: {source}", file=sys.stderr)
        sys.exit(2)

    files, skipped = collect(source)
    print(f"源目录: {source}")
    print(f"待打包文件: {len(files)} 个，原始大小 {sum(p.stat().st_size for p, _ in files) / 1048576:.1f} MB")
    print(f"已排除: {len(skipped)} 项" + (f"（{', '.join(skipped[:5])}...）" if skipped else ""))

    zip_name = f"PassVault-v{a.version}-win64.zip"
    zip_path = outdir / zip_name
    top = source.name
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p, rel in files:
            z.write(p, str(Path(top) / rel))
        # MIT 要求随每个副本附带许可声明；与 Electron 自带的 LICENSE 区分命名
        lic = Path(__file__).resolve().parents[1] / "LICENSE"
        if lic.exists():
            z.write(lic, str(Path(top) / "LICENSE-PassVault.txt"))
    # 写完再验一次：包里绝不能出现私有数据
    with zipfile.ZipFile(zip_path) as z:
        bad = [n for n in z.namelist() if is_forbidden(Path(n))]
        if bad:
            zip_path.unlink(missing_ok=True)
            print(f"[致命] 压缩包内发现私有数据，已删除 zip: {bad[:5]}", file=sys.stderr)
            sys.exit(2)
        count = len(z.namelist())

    h = hashlib.sha256()
    with zip_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    digest = h.hexdigest()
    (outdir / "SHA256SUMS.txt").write_text(
        f"# PassVault v{a.version} Windows x64 免安装版\n"
        f"# 校验: Get-FileHash .\\{zip_name} -Algorithm SHA256\n"
        f"{digest}  {zip_name}\n", encoding="utf-8")

    print(f"\n[完成] {zip_path}")
    print(f"  包内文件 {count} 个，大小 {zip_path.stat().st_size / 1048576:.1f} MB")
    print(f"  SHA256: {digest}")
    print(f"  校验文件: {outdir / 'SHA256SUMS.txt'}")


if __name__ == "__main__":
    main()
