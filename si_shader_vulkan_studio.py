"""
SI-Shader-Vulkan-Studio v1.0 — Universal PC Game Stutter, MPO & DXVK Compatibility Studio
Solves global Windows 11/10 gaming problems across ALL Steam, Epic, Xbox & GOG games:
  1. Bloated / corrupted NVIDIA, AMD & DirectX Shader Caches (clean + rebuild safely)
  2. Windows Multiplane Overlay (MPO) dual-monitor flicker & micro-stutter + live Overlay Conflict scan
  3. Slow single-thread DX9/DX10/DX11 games -> 1-Click PE-matched DXVK (Vulkan) + low-latency dxvk.conf
  4. Classic 32-bit 2GB RAM crash -> Real PE Header 4GB Large Address Aware patcher + PE checksum fix
  5. Strict Anti-Cheat Ban Shield & SHA-256 verified 1-Click Restore
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import tkinter as tk
import winreg
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any
from urllib.parse import unquote, urlparse

from vulkan_pe_engine import (
    apply_4gb_laa_patch,
    clean_shader_caches,
    inspect_mpo_status,
    inspect_pe_binary,
    install_dxvk_to_game,
    rollback_game_studio,
    scan_active_overlay_processes,
    scan_game_anticheat,
    scan_shader_caches,
    toggle_mpo_fix,
)

APP_VERSION = "1.0.0"


def _find_main_exe(game_dir: Path) -> Path | None:
    skip = ("unins", "crash", "redist", "setup", "helper", "launcher")
    cands = []
    for pat in ("*.exe", "Binaries/Win64/*.exe", "Binaries/Win32/*.exe"):
        for p in game_dir.glob(pat):
            if not any(w in p.name.lower() for w in skip):
                cands.append(p)
    if not cands:
        cands = list(game_dir.glob("*.exe"))
    return max(cands, key=lambda p: p.stat().st_size if p.exists() else 0) if cands else None


def discover_pc_games(extra_dirs: list[Path] | None = None, limit: int = 35) -> list[dict[str, Any]]:
    """Auto-discover Steam, Epic, Xbox & GOG games on Windows without manual browsing."""
    found: list[tuple[str, str, Path]] = []
    seen: set[str] = set()

    def _add(src: str, title: str, path: Path) -> None:
        if not path.exists() or not path.is_dir():
            return
        k = str(path.resolve()).lower()
        if k not in seen:
            seen.add(k)
            found.append((src, title, path))

    steam_roots = [Path(r"C:\Program Files (x86)\Steam")]
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as regk:
            sp, _ = winreg.QueryValueEx(regk, "SteamPath")
            if sp:
                steam_roots.insert(0, Path(str(sp)))
    except OSError:
        pass

    for sr in steam_roots:
        vdf = sr / "steamapps" / "libraryfolders.vdf"
        libs = [sr / "steamapps"]
        if vdf.exists():
            txt = vdf.read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r'"path"\s+"([^"]+)"', txt):
                p = Path(m.group(1).replace("\\\\", "\\")) / "steamapps"
                if p.exists() and p not in libs:
                    libs.append(p)
        for lp in libs:
            for acf in lp.glob("appmanifest_*.acf"):
                txt = acf.read_text(encoding="utf-8", errors="replace")
                nm = re.search(r'"name"\s+"([^"]+)"', txt)
                id_m = re.search(r'"installdir"\s+"([^"]+)"', txt)
                if nm and id_m and "steamworks" not in nm.group(1).lower():
                    _add("Steam", nm.group(1), lp / "common" / id_m.group(1))

    epic = Path(r"C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests")
    if epic.exists():
        for item in epic.glob("*.item"):
            try:
                d = json.loads(item.read_text(encoding="utf-8", errors="replace"))
                if d.get("DisplayName") and d.get("InstallLocation"):
                    _add("Epic", d["DisplayName"], Path(d["InstallLocation"]))
            except Exception:
                continue

    for root, src in ((Path(r"C:\XboxGames"), "Xbox"), (Path(r"C:\GOG Games"), "GOG")):
        if root.exists():
            for child in root.iterdir():
                if child.is_dir():
                    c = child / "Content"
                    _add(src, child.name, c if c.exists() else child)

    if extra_dirs:
        for ed in extra_dirs:
            _add("Custom", ed.name, ed)

    out: list[dict[str, Any]] = []
    for src, title, gpath in found[:limit]:
        exe = _find_main_exe(gpath)
        pe = inspect_pe_binary(exe) if exe else {"ok": False}
        out.append({
            "source": src,
            "title": title,
            "path": str(gpath),
            "exe_rel": str(exe.relative_to(gpath)) if exe else None,
            "arch": pe.get("arch", "?"),
            "dx_apis": pe.get("dx_apis", []),
            "needs_4gb_patch": bool(pe.get("needs_4gb_patch")),
            "dxvk_eligible": bool(pe.get("dxvk_eligible")),
        })
    return out


def audit_system_and_game(game_dir: Path | None) -> dict[str, Any]:
    """Full pre-flight system + PE executable inspection."""
    caches = scan_shader_caches()
    mpo = inspect_mpo_status()
    overlays = scan_active_overlay_processes()
    game_audit: dict[str, Any] = {"ok": False}

    if game_dir and game_dir.exists() and game_dir.is_dir():
        exe = _find_main_exe(game_dir)
        pe = inspect_pe_binary(exe) if exe else {"ok": False, "error": "No .exe found"}
        ac = scan_game_anticheat(game_dir)
        bak_exists = (exe.parent / "si_shader_studio_backup" / "manifest.json").exists() if exe else False
        game_audit = {
            "ok": True,
            "game_dir": str(game_dir),
            "exe": str(exe) if exe else None,
            "pe": pe,
            "anticheat": ac,
            "backup_exists": bak_exists,
        }

    return {
        "ok": True,
        "shader_caches": caches,
        "mpo": mpo,
        "active_overlays": overlays,
        "game": game_audit,
    }


def apply_selected_optimizations(
    game_dir: Path | None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute global Windows & selected game optimizations cleanly with Ban Shield + SHA-256 backups."""
    opts = {
        "clean_shader_cache": True,
        "disable_mpo_stutter": True,
        "install_dxvk": False,
        "patch_4gb_laa": True,
        **(options or {}),
    }
    report: dict[str, Any] = {"ok": True, "steps": {}}

    if opts.get("clean_shader_cache"):
        report["steps"]["shader_cache"] = clean_shader_caches()

    if opts.get("disable_mpo_stutter"):
        report["steps"]["mpo_fix"] = toggle_mpo_fix(disable_mpo=True)

    if game_dir and game_dir.exists():
        exe = _find_main_exe(game_dir)
        ac = scan_game_anticheat(game_dir)
        if not ac.get("safe_to_inject") and (opts.get("install_dxvk") or opts.get("patch_4gb_laa")):
            return {
                "ok": False,
                "blocked_by_anticheat": True,
                "hits": ac.get("hits", []),
                "error": "Anti-Cheat detected! Game DLL/EXE changes aborted (system cache clean safe).",
                "steps": report["steps"],
            }
        if opts.get("install_dxvk") and exe:
            dx_res = install_dxvk_to_game(game_dir, exe_rel_path=str(exe.relative_to(game_dir)))
            report["steps"]["dxvk"] = dx_res
            if not dx_res.get("ok"):
                report["ok"] = False
                report["error"] = dx_res.get("error")
        if opts.get("patch_4gb_laa") and exe:
            # Snapshot backup before patching EXE if DXVK didn't already snapshot
            if not (exe.parent / "si_shader_studio_backup" / "manifest.json").exists():
                import json as _j, shutil as _sh
                from datetime import datetime as _dt, timezone as _tz
                from vulkan_pe_engine import sha256_file as _sha
                bdir = exe.parent / "si_shader_studio_backup"
                bdir.mkdir(parents=True, exist_ok=True)
                _sh.copy2(exe, bdir / exe.name)
                (bdir / "manifest.json").write_text(_j.dumps({
                    "created_at": _dt.now(_tz.utc).isoformat(),
                    "exe_path": str(exe),
                    "exe_sha256": _sha(exe),
                    "existed_before": {},
                    "created_by_studio": [],
                }, indent=2), encoding="utf-8")
            report["steps"]["laa_4gb"] = apply_4gb_laa_patch(exe)

    return report


WEB_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SI-Shader-Vulkan-Studio — Universal Game Stutter, MPO & DXVK 1-Click Fixer</title>
<style>
:root {
  --bg: #070c14; --panel: #0d1624; --card: #121e31; --border: #223554;
  --accent: #00e5a3; --blue: #38bdf8; --amber: #f59e0b; --red: #ef4444;
  --text: #eef4ff; --muted: #8ea5c8;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }
body { background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
.topbar {
  height: 60px; background: #0a111d; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between; padding: 0 22px;
}
.brand { display: flex; align-items: center; gap: 12px; font-weight: 800; font-size: 19px; }
.pill { background: rgba(0,229,163,0.14); color: var(--accent); border: 1px solid rgba(0,229,163,0.45); padding: 4px 11px; border-radius: 999px; font-size: 12px; font-weight: 700; }
.pill.blue { background: rgba(56,189,248,0.14); color: var(--blue); border-color: rgba(56,189,248,0.45); }
.main { display: flex; flex: 1; overflow: hidden; }
.sidebar {
  width: 315px; background: var(--panel); border-right: 1px solid var(--border);
  padding: 16px 14px; display: flex; flex-direction: column; gap: 8px;
}
.nav-btn {
  text-align: left; padding: 13px 14px; border-radius: 10px; border: 1px solid transparent;
  background: transparent; color: var(--muted); font-size: 14px; font-weight: 600; cursor: pointer;
  display: flex; justify-content: space-between; align-items: center;
}
.nav-btn.active { background: #16263f; color: #fff; border-color: var(--accent); box-shadow: inset 3px 0 0 var(--accent); }
.content { flex: 1; padding: 20px 26px; overflow-y: auto; display: flex; flex-direction: column; gap: 15px; }
.path-bar { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 11px 16px; display: flex; align-items: center; gap: 10px; }
.path-input { flex: 1; background: #08101c; border: 1px solid #2b4268; color: var(--text); padding: 9px 12px; border-radius: 8px; font-family: Consolas, monospace; font-size: 13px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 18px 20px; }
.card h2 { font-size: 18px; margin-bottom: 8px; color: #fff; }
.sub { font-size: 13.5px; color: var(--muted); margin-bottom: 12px; line-height: 1.45; }
.grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
.metric-val { font-size: 25px; font-weight: 800; color: var(--accent); margin: 3px 0; }
.metric-lbl { font-size: 11.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.6px; }
.btn { padding: 10px 15px; border-radius: 8px; border: none; font-weight: 700; font-size: 13.5px; cursor: pointer; background: var(--accent); color: #041b12; }
.btn.blue { background: var(--blue); color: #041926; }
.btn.warn { background: var(--amber); color: #1d1202; }
.btn.sec { background: #1c2e4a; color: #dbeafe; border: 1px solid #355280; }
.toggle-row { display: flex; align-items: center; justify-content: space-between; gap: 14px; padding: 11px 14px; background: #0c1524; border: 1px solid #223554; border-radius: 10px; margin-bottom: 8px; }
.toggle-row input[type="checkbox"] { width: 20px; height: 20px; accent-color: var(--accent); cursor: pointer; }
.issue-row { background: #0c1524; border: 1px solid #263959; border-left: 4px solid var(--amber); border-radius: 10px; padding: 11px 14px; margin-bottom: 8px; }
.issue-row.HIGH { border-left-color: var(--red); }
.issue-row.FIXED { border-left-color: var(--accent); }
.tag { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11.5px; font-weight: 700; margin-right: 6px; }
.tag.HIGH { background: rgba(239,68,68,0.2); color: #fca5a5; }
.tag.MEDIUM { background: rgba(245,158,11,0.2); color: #fcd34d; }
.tag.FIXED { background: rgba(0,229,163,0.18); color: var(--accent); }
.game-item { display: flex; justify-content: space-between; align-items: center; padding: 10px 13px; background: #0b1321; border: 1px solid #1e3150; border-radius: 9px; margin-bottom: 7px; cursor: pointer; }
.game-item:hover { border-color: var(--blue); }
.toast { padding: 11px 16px; border-radius: 10px; font-size: 13.5px; font-weight: 600; display: none; }
.toast.ok { display: block; background: rgba(0,229,163,0.14); border: 1px solid var(--accent); color: var(--accent); }
.toast.err { display: block; background: rgba(239,68,68,0.16); border: 1px solid var(--red); color: #fca5a5; }
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">
    <span style="color:var(--accent)">&#9889; SI-SHADER-VULKAN-STUDIO</span>
    <span class="pill">GLOBAL PC STUTTER & DXVK FIXER</span>
    <span class="pill blue" id="mpoPill">MPO CHECKING...</span>
  </div>
  <div style="color:var(--muted);font-size:12.5px">github.com/Grokeador/si-shader-vulkan-studio</div>
</div>

<div class="main">
  <div class="sidebar">
    <button class="nav-btn active" onclick="showTab(0)" id="nav0">Step 1: PC Caches & Games</button>
    <button class="nav-btn" onclick="showTab(1)" id="nav1">Step 2: Yes / No Fixes</button>
    <button class="nav-btn" onclick="showTab(2)" id="nav2">Step 3: Binary PE & Overlays</button>
    <button class="nav-btn" onclick="showTab(3)" id="nav3">Bonus: Cache & MPO Proof</button>

    <div style="margin-top:auto;background:#0a1220;border:1px solid #223556;border-radius:12px;padding:13px">
      <div style="font-size:11.5px;color:var(--muted);margin-bottom:8px">UNIVERSAL 1-CLICK ENGINE</div>
      <button class="btn" style="width:100%;margin-bottom:8px" onclick="applyAll()">&#9889; 1-Click Apply Fixes</button>
      <button class="btn blue" style="width:100%;margin-bottom:8px" onclick="cleanCachesOnly()">&#129529; Clean Shader Caches Only</button>
      <button class="btn warn" style="width:100%" onclick="rollbackGame()">&#8634; Restore Game Originals</button>
    </div>
  </div>

  <div class="content">
    <div class="path-bar">
      <span style="font-size:12.5px;font-weight:700;color:var(--blue)">OPTIONAL GAME FOLDER</span>
      <input class="path-input" id="gamePath" placeholder="Select any Steam / Epic / GOG game below (or leave blank for global Windows fixes)">
      <button class="btn sec" onclick="pickGameBrowse()">Browse...</button>
      <button class="btn sec" onclick="fetchState()">Scan</button>
    </div>
    <div id="toastBox" class="toast"></div>
    <div id="tabContent"></div>
  </div>
</div>

<script>
let currentTab = 0;
let stateData = null;
const opts = {
  clean_shader_cache: true,
  disable_mpo_stutter: true,
  install_dxvk: true,
  patch_4gb_laa: true
};

function setToast(msg, ok=true) {
  const b = document.getElementById('toastBox');
  b.textContent = msg;
  b.className = 'toast ' + (ok ? 'ok' : 'err');
}

function showTab(idx) {
  currentTab = idx;
  for (let i = 0; i < 4; i++) document.getElementById('nav' + i).className = 'nav-btn' + (i === idx ? ' active' : '');
  renderTab();
}

async function fetchState() {
  const gd = encodeURIComponent(document.getElementById('gamePath').value || '');
  const res = await fetch('/api/state?game_dir=' + gd);
  stateData = await res.json();
  document.getElementById('mpoPill').textContent = stateData.audit.mpo.mpo_disabled ? 'MPO: DISABLED (CLEAN)' : 'MPO: ACTIVE (STUTTER RISK)';
  renderTab();
}

function selectGame(p) {
  document.getElementById('gamePath').value = p;
  fetchState();
}

async function pickGameBrowse() {
  const res = await fetch('/api/browse', {method: 'POST'});
  const d = await res.json();
  if (d.path) { document.getElementById('gamePath').value = d.path; fetchState(); }
}

async function cleanCachesOnly() {
  const res = await fetch('/api/clean-cache', {method: 'POST'});
  const d = await res.json();
  setToast('Freed ' + d.freed_mb + ' MB across ' + d.removed_files + ' stale shader files!', true);
  await fetchState();
}

async function applyAll() {
  setToast('Cleaning stale shader caches, preparing MPO stutter fix & checking game PE headers...', true);
  const res = await fetch('/api/apply', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({game_dir: document.getElementById('gamePath').value, options: opts})
  });
  const d = await res.json();
  setToast(d.ok ? 'All selected global Windows & game optimizations applied!' : ('Note / Blocked: ' + (d.error || 'Error')), d.ok);
  await fetchState();
}

async function rollbackGame() {
  const res = await fetch('/api/rollback', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({game_dir: document.getElementById('gamePath').value})
  });
  const d = await res.json();
  setToast(d.ok ? ('Restored SHA-256 verified originals: ' + (d.restored || []).join(', ')) : d.error, d.ok);
  await fetchState();
}

function renderTab() {
  if (!stateData) return;
  const a = stateData.audit;
  const games = stateData.games || [];
  const el = document.getElementById('tabContent');

  if (currentTab === 0) {
    const gamesHtml = games.length ? games.map(g => `
      <div class="game-item" onclick="selectGame(${JSON.stringify(g.path).replace(/"/g, '&quot;')})">
        <div>
          <strong>${g.title}</strong> <span class="tag MEDIUM">${g.source} • ${g.arch}</span>
          <div style="font-size:12px;color:var(--muted);font-family:Consolas">${g.path}</div>
        </div>
        <span class="tag ${g.dxvk_eligible ? 'FIXED' : 'MEDIUM'}">${g.dxvk_eligible ? 'DXVK READY' : (g.dx_apis.join(', ') || 'WIN32')}</span>
      </div>`).join('') : '<div class="sub">Global Windows Shader Cache & MPO fixes work even without picking a game, or browse any game folder above.</div>';

    el.innerHTML = `
      <div class="grid-4">
        <div class="card"><div class="metric-lbl">Shader Cache Bloat</div><div class="metric-val">${a.shader_caches.total_mb} MB</div><div class="metric-lbl">${a.shader_caches.total_files} Cached Files</div></div>
        <div class="card"><div class="metric-lbl">Windows MPO State</div><div class="metric-val" style="font-size:19px;color:${a.mpo.mpo_disabled ? 'var(--accent)' : '#fcd34d'}">${a.mpo.mpo_disabled ? 'STUTTER-FREE' : 'DEFAULT RISK'}</div><div class="metric-lbl">Multi-Monitor Check</div></div>
        <div class="card"><div class="metric-lbl">Active Overlays</div><div class="metric-val" style="color:${a.active_overlays.length ? '#fcd34d' : 'var(--accent)'}">${a.active_overlays.length}</div><div class="metric-lbl">RTSS / Discord / Medal</div></div>
        <div class="card"><div class="metric-lbl">Games Scanned</div><div class="metric-val">${games.length}</div><div class="metric-lbl">Steam / Epic / Xbox</div></div>
      </div>
      <div class="card">
        <h2>Step 1: Global Windows Health & Installed PC Games</h2>
        <p class="sub">Fix Windows shader stutter & dual-monitor lag globally, or pick any game below to inspect its exact PE headers and unlock DXVK Vulkan / 4GB RAM.</p>
        <div style="max-height:280px;overflow-y:auto">${gamesHtml}</div>
      </div>`;
  } else if (currentTab === 1) {
    const row = (k, t, d) => `
      <div class="toggle-row">
        <div><strong>${t}</strong><div class="sub" style="margin:2px 0 0">${d}</div></div>
        <input type="checkbox" ${opts[k] ? 'checked' : ''} onchange="opts['${k}']=this.checked">
      </div>`;
    el.innerHTML = `
      <div class="card">
        <h2>Step 2: Simple Yes / No Optimization Switches</h2>
        <p class="sub">Everything backs up untouched game files with SHA-256 verification and blocks Anti-Cheat titles automatically.</p>
        ${row('clean_shader_cache', 'Purge Corrupted NVIDIA / AMD / DirectX Shader Caches', 'Clears bloated driver & Windows D3DSCache folders that trigger post-update 0.1% low stutter.')}
        ${row('disable_mpo_stutter', 'Fix Multi-Monitor MPO Flicker & Stutter (OverlayTestMode=5)', 'Applies or exports clean 1-click disable/restore .reg files to stop Windows DWM multi-monitor stutter.')}
        ${row('install_dxvk', 'Auto-Install Official DXVK (DirectX 9/10/11 -> Vulkan) Into Game', 'Inspects game PE imports to match x32/x64 DLLs automatically and writes tuned dxvk.conf.')}
        ${row('patch_4gb_laa', 'Unlock 4GB Memory Limit in Classic 32-bit Game EXEs (LAA Patch)', 'Flips the Windows LARGE_ADDRESS_AWARE PE flag and recalculates binary checksums to cure 2GB crashes.')}
      </div>`;
  } else if (currentTab === 2) {
    const g = a.game;
    const pe = (g && g.pe) ? g.pe : {};
    const ovHtml = a.active_overlays.length ? a.active_overlays.map(o => `<div class="issue-row MEDIUM"><strong>${o.process}</strong> — ${o.reason}</div>`).join('') : '<div class="issue-row FIXED"><span class="tag FIXED">CLEAR</span>No conflicting overlay hooks running right now.</div>';
    el.innerHTML = `
      <div class="card">
        <h2>Step 3: Live PE Executable Analyzer & Overlay Conflict Guard</h2>
        <p class="sub">Directly parses binary headers & Import Tables instead of guessing 32-bit vs 64-bit or DX9 vs DX11.</p>
        <pre style="background:#070c14;border:1px solid #223554;border-radius:10px;padding:12px;font-family:Consolas,monospace;font-size:12.5px;color:#cbd5e1;margin-bottom:12px">${JSON.stringify(g.ok ? {exe: g.exe, arch: pe.arch, dx_apis: pe.dx_apis, needs_4gb_patch: pe.needs_4gb_patch, dxvk_eligible: pe.dxvk_eligible, anticheat_safe: g.anticheat.safe_to_inject} : {note: 'Pick a game folder in Step 1 to inspect its PE binary'}, null, 2)}</pre>
        ${ovHtml}
      </div>`;
  } else if (currentTab === 3) {
    const rows = a.shader_caches.entries.map(c => `
      <div class="issue-row ${c.size_mb > 200 ? 'MEDIUM' : 'FIXED'}">
        <strong>${c.label}</strong> <span style="color:var(--blue);font-family:Consolas">[${c.size_mb} MB • ${c.files} files]</span>
        <div class="sub" style="margin:3px 0 0">${c.path}</div>
      </div>`).join('');
    el.innerHTML = `
      <div class="card">
        <h2>Bonus: Real-Time Driver Cache Map & Multi-Monitor MPO Registry</h2>
        <p class="sub">Every NVIDIA DXCache/GLCache, AMD DxCache/VkCache, Intel ShaderCache & Windows D3DSCache path inspected live.</p>
        ${rows}
      </div>`;
  }
}

const _up = new URLSearchParams(window.location.search);
if (_up.has('tab')) {
  const _t = parseInt(_up.get('tab'), 10);
  if (!Number.isNaN(_t) && _t >= 0 && _t <= 3) showTab(_t);
}
fetchState();
</script>
</body>
</html>
"""


def start_web_server(initial_dir: Path | None = None, port: int = 8794) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, data: dict[str, Any], code: int = 200) -> None:
            payload = json.dumps(data).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path in ("/", "/index.html"):
                html = WEB_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            if parsed.path == "/api/state":
                qs = parsed.query
                gdir = initial_dir
                if "game_dir=" in qs:
                    val = unquote(qs.split("game_dir=", 1)[1].split("&", 1)[0]).strip()
                    if val:
                        gdir = Path(val)
                self._send_json({
                    "ok": True,
                    "audit": audit_system_and_game(gdir),
                    "games": discover_pc_games(extra_dirs=[gdir] if gdir and gdir.exists() else None),
                })
                return
            self.send_error(404)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            body = json.loads(raw.decode("utf-8")) if raw else {}
            gdir = Path(body["game_dir"]) if body.get("game_dir") else None
            if self.path == "/api/clean-cache":
                self._send_json(clean_shader_caches())
                return
            if self.path == "/api/apply":
                self._send_json(apply_selected_optimizations(gdir, options=body.get("options")))
                return
            if self.path == "/api/rollback":
                exe = _find_main_exe(gdir) if gdir and gdir.exists() else None
                self._send_json(rollback_game_studio(exe.parent if exe else (gdir or Path("."))))
                return
            if self.path == "/api/browse":
                picked = ""
                try:
                    r = tk.Tk()
                    r.withdraw()
                    picked = filedialog.askdirectory()
                    r.destroy()
                except Exception:
                    pass
                self._send_json({"ok": True, "path": picked})
                return
            self.send_error(404)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def launch_tk_gui(initial_dir: Path | None = None) -> None:
    root = tk.Tk()
    root.title(f"SI-Shader-Vulkan-Studio v{APP_VERSION} — Global Game Stutter & DXVK Studio")
    root.geometry("980x680")
    root.configure(bg="#070c14")
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TFrame", background="#070c14")
    style.configure("TLabel", background="#070c14", foreground="#eef4ff", font=("Segoe UI", 10))
    style.configure("Header.TLabel", font=("Segoe UI", 15, "bold"), foreground="#00e5a3")
    style.configure("TCheckbutton", background="#070c14", foreground="#e2ecff", font=("Segoe UI", 10))

    top = ttk.Frame(root, padding=14)
    top.pack(fill=tk.X)
    ttk.Label(top, text="SI-Shader-Vulkan-Studio — Universal Shader Cache, MPO & DXVK Studio", style="Header.TLabel").pack(anchor=tk.W)

    row = ttk.Frame(root, padding=(14, 4))
    row.pack(fill=tk.X)
    dir_var = tk.StringVar(value=str(initial_dir) if initial_dir else "")
    ttk.Entry(row, textvariable=dir_var, width=70).pack(side=tk.LEFT, padx=(0, 8))
    ttk.Button(row, text="Browse Game", command=lambda: (p := filedialog.askdirectory()) and dir_var.set(p)).pack(side=tk.LEFT)

    chks = ttk.Frame(root, padding=(14, 4))
    chks.pack(fill=tk.X)
    v_cache = tk.BooleanVar(value=True)
    v_mpo = tk.BooleanVar(value=True)
    v_dxvk = tk.BooleanVar(value=True)
    v_laa = tk.BooleanVar(value=True)
    ttk.Checkbutton(chks, text="YES: Purge Corrupted NVIDIA / AMD / DirectX Shader Caches", variable=v_cache).pack(anchor=tk.W)
    ttk.Checkbutton(chks, text="YES: Apply Multi-Monitor MPO Stutter Fix (.reg + direct if Admin)", variable=v_mpo).pack(anchor=tk.W)
    ttk.Checkbutton(chks, text="YES: Install PE-Matched Official DXVK Vulkan Wrapper for Selected Game", variable=v_dxvk).pack(anchor=tk.W)
    ttk.Checkbutton(chks, text="YES: Patch 32-bit Game EXE with 4GB Large Address Aware + Checksum", variable=v_laa).pack(anchor=tk.W)

    box = scrolledtext.ScrolledText(root, bg="#0b1322", fg="#cde2ff", font=("Consolas", 10), height=20)
    box.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

    def _show(d: Any) -> None:
        box.delete("1.0", tk.END)
        box.insert(tk.END, json.dumps(d, indent=2))

    btns = ttk.Frame(root, padding=14)
    btns.pack(fill=tk.X)
    ttk.Button(btns, text="1. Scan PC & Game", command=lambda: _show(audit_system_and_game(Path(dir_var.get()) if dir_var.get() else None))).pack(side=tk.LEFT, padx=4)
    ttk.Button(btns, text="2. 1-Click Apply Fixes", command=lambda: _show(apply_selected_optimizations(Path(dir_var.get()) if dir_var.get() else None, {"clean_shader_cache": v_cache.get(), "disable_mpo_stutter": v_mpo.get(), "install_dxvk": v_dxvk.get(), "patch_4gb_laa": v_laa.get()}))).pack(side=tk.LEFT, padx=4)
    ttk.Button(btns, text="3. Restore Game Backup", command=lambda: _show(rollback_game_studio(Path(dir_var.get())))).pack(side=tk.LEFT, padx=4)

    _show(audit_system_and_game(initial_dir))
    root.mainloop()


def main() -> None:
    parser = argparse.ArgumentParser(description="SI-Shader-Vulkan-Studio: Global Windows Shader Cache, MPO & DXVK Studio")
    parser.add_argument("command", nargs="?", default="web", choices=["web", "tk", "audit", "clean-cache", "apply", "rollback"])
    parser.add_argument("--game-dir", default="")
    parser.add_argument("--port", type=int, default=8794)
    args = parser.parse_args()

    gdir = Path(args.game_dir) if args.game_dir else None
    if args.command == "audit":
        print(json.dumps(audit_system_and_game(gdir), indent=2))
    elif args.command == "clean-cache":
        print(json.dumps(clean_shader_caches(), indent=2))
    elif args.command == "apply":
        res = apply_selected_optimizations(gdir)
        print(json.dumps(res, indent=2))
        if not res.get("ok"):
            sys.exit(1)
    elif args.command == "rollback":
        exe = _find_main_exe(gdir) if gdir and gdir.exists() else None
        res = rollback_game_studio(exe.parent if exe else (gdir or Path(".")))
        print(json.dumps(res, indent=2))
        if not res.get("ok"):
            sys.exit(1)
    elif args.command == "tk":
        launch_tk_gui(gdir)
    elif args.command == "web":
        srv = start_web_server(gdir, port=args.port)
        url = f"http://127.0.0.1:{args.port}/"
        print(f"SI-Shader-Vulkan-Studio live at {url}", flush=True)
        for browser in (
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        ):
            if os.path.exists(browser):
                threading.Thread(target=lambda b=browser: subprocess.Popen([b, f"--app={url}"]), daemon=True).start()
                break
        srv.serve_forever()


if __name__ == "__main__":
    main()
