"""
Real PE Binary Analyzer, 32-bit 4GB LAA Patcher, Windows Shader Cache Cleaner,
MPO Multi-Monitor Registry Helper, Active Overlay Detector & Official DXVK Installer.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tarfile
import urllib.request
import winreg
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DXVK_RELEASES_API = "https://api.github.com/repos/doitsujin/dxvk/releases/latest"
LOCAL_APP_ROOT = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SI-Shader-Vulkan-Studio"

ANTICHEAT_SIGNATURES: dict[str, str] = {
    "easyanticheat": "EasyAntiCheat (EOS / Kernel Ban Risk)",
    "eac_launcher": "EasyAntiCheat Launcher",
    "battleye": "BattlEye Anti-Cheat (Kernel Ban Risk)",
    "beclient": "BattlEye Client",
    "vgk.sys": "Riot Vanguard (Kernel Anti-Cheat)",
    "vgc.exe": "Riot Vanguard Client",
    "faceit": "FACEIT Anti-Cheat",
    "gameguard": "nProtect GameGuard",
    "xigncode": "XIGNCODE3",
    "ricochet": "COD RICOCHET Driver",
}

KNOWN_CONFLICT_PROCESSES: dict[str, str] = {
    "rtss.exe": "RivaTuner Statistics Server (Overlay/Hook Conflict Risk)",
    "msiafterburner.exe": "MSI Afterburner Telemetry Hook",
    "medal.exe": "Medal Clip Overlay",
    "gamebar.exe": "Xbox Game Bar Overlay",
    "nvidia overlay.exe": "NVIDIA App Overlay",
    "discord.exe": "Discord In-Game Overlay (Disable Overlay if stuttering)",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def inspect_pe_binary(exe_path: Path) -> dict[str, Any]:
    """Parse real Windows PE headers & Import Table to detect x86/x64, 4GB LAA flag, and DirectX APIs."""
    if not exe_path.exists() or not exe_path.is_file():
        return {"ok": False, "error": f"Executable not found: {exe_path}"}
    data = exe_path.read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        return {"ok": False, "error": "Not a valid Windows MZ executable"}
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
        return {"ok": False, "error": "Invalid PE signature"}

    machine, num_sec, _, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
    arch = "x64" if machine == 0x8664 else ("x86" if machine == 0x014C else f"0x{machine:04X}")
    laa_enabled = bool(characteristics & 0x0020)
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    is_pe32_plus = magic == 0x020B

    # Parse sections for RVA -> file offset translation
    sec_off = opt_off + opt_size
    sections: list[tuple[int, int, int]] = []
    for i in range(num_sec):
        if sec_off + (i + 1) * 40 > len(data):
            break
        _, vsize, va, rsz, rptr = struct.unpack_from("<8sIIII", data, sec_off + i * 40)
        sections.append((va, max(vsize, rsz), rptr))

    def _rva2off(rva: int) -> int | None:
        for va, span, rptr in sections:
            if va <= rva < va + span:
                off = rptr + (rva - va)
                return off if off < len(data) else None
        return None

    # Read Import Directory RVA (offset 96+8 in PE32 = 104, 112+8 in PE32+ = 120)
    imp_dir_off = opt_off + (120 if is_pe32_plus else 104)
    imported_dlls: list[str] = []
    if imp_dir_off + 8 <= len(data):
        imp_rva, imp_sz = struct.unpack_from("<II", data, imp_dir_off)
        if imp_rva and imp_sz:
            desc_off = _rva2off(imp_rva)
            if desc_off is not None:
                for idx in range(256):
                    entry_off = desc_off + idx * 20
                    if entry_off + 20 > len(data):
                        break
                    orig_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, entry_off)
                    if not (orig_thunk or name_rva or first_thunk):
                        break
                    noff = _rva2off(name_rva)
                    if noff is not None:
                        dll_name = data[noff : noff + 64].split(b"\x00", 1)[0].decode("ascii", errors="ignore").lower()
                        if dll_name:
                            imported_dlls.append(dll_name)

    dx_apis: list[str] = []
    for api_dll in ("d3d9.dll", "d3d10.dll", "d3d10_1.dll", "d3d11.dll", "d3d12.dll", "dxgi.dll"):
        if api_dll in imported_dlls:
            dx_apis.append(api_dll)

    return {
        "ok": True,
        "exe": str(exe_path),
        "arch": arch,
        "is_32bit": arch == "x86",
        "characteristics_off": pe_off + 22,
        "characteristics": characteristics,
        "laa_4gb_enabled": laa_enabled,
        "needs_4gb_patch": (arch == "x86" and not laa_enabled),
        "dx_apis": dx_apis,
        "dxvk_eligible": any(a in dx_apis for a in ("d3d9.dll", "d3d10.dll", "d3d10_1.dll", "d3d11.dll")) and ("d3d12.dll" not in dx_apis),
    }


def _recompute_pe_checksum(buf: bytearray) -> None:
    """Compute standard Windows PE OptionalHeader CheckSum via imagehlp.CheckSumMappedFile (or fallback)."""
    pe_off = struct.unpack_from("<I", buf, 0x3C)[0]
    ck_off = pe_off + 24 + 64
    struct.pack_into("<I", buf, ck_off, 0)
    try:
        img = ctypes.windll.imagehlp
        hdr_sum = ctypes.c_ulong(0)
        chk_sum = ctypes.c_ulong(0)
        raw_arr = (ctypes.c_ubyte * len(buf)).from_buffer(buf)
        img.CheckSumMappedFile(raw_arr, len(buf), ctypes.byref(hdr_sum), ctypes.byref(chk_sum))
        struct.pack_into("<I", buf, ck_off, chk_sum.value)
    except Exception:
        pass


def apply_4gb_laa_patch(exe_path: Path) -> dict[str, Any]:
    """Set IMAGE_FILE_LARGE_ADDRESS_AWARE (0x0020) inside 32-bit PE header and fix PE CheckSum."""
    info = inspect_pe_binary(exe_path)
    if not info.get("ok"):
        return info
    if not info["is_32bit"]:
        return {"ok": True, "skipped": True, "reason": "Executable is already 64-bit (no 2GB limit)."}
    if info["laa_4gb_enabled"]:
        return {"ok": True, "skipped": True, "reason": "4GB Large Address Aware bit is already enabled."}

    buf = bytearray(exe_path.read_bytes())
    off = int(info["characteristics_off"])
    new_chars = int(info["characteristics"]) | 0x0020
    struct.pack_into("<H", buf, off, new_chars)
    _recompute_pe_checksum(buf)
    exe_path.write_bytes(bytes(buf))
    return {"ok": True, "patched": True, "new_characteristics": f"0x{new_chars:04X}"}


def scan_shader_caches(extra_dirs: list[Path] | None = None) -> dict[str, Any]:
    """Inspect real NVIDIA, AMD, Intel & Windows DirectX shader cache directories and total bloat MB."""
    local = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    locallow = Path.home() / "AppData" / "LocalLow"
    candidates = [
        ("NVIDIA DXCache", local / "NVIDIA" / "DXCache"),
        ("NVIDIA GLCache", local / "NVIDIA" / "GLCache"),
        ("NVIDIA PerDriver DXCache", locallow / "NVIDIA" / "PerDriverVersion" / "DXCache"),
        ("AMD DxCache", local / "AMD" / "DxCache"),
        ("AMD VkCache", local / "AMD" / "VkCache"),
        ("Windows D3DSCache", local / "D3DSCache"),
        ("Intel ShaderCache", local / "Intel" / "ShaderCache"),
    ]
    if extra_dirs:
        candidates = [(f"Custom Cache ({d.name})", d) for d in extra_dirs]

    entries: list[dict[str, Any]] = []
    total_bytes = 0
    total_files = 0
    for label, d in candidates:
        size_b = 0
        fcount = 0
        if d.exists() and d.is_dir():
            for p in d.rglob("*"):
                if p.is_file():
                    try:
                        size_b += p.stat().st_size
                        fcount += 1
                    except OSError:
                        pass
        total_bytes += size_b
        total_files += fcount
        entries.append({
            "label": label,
            "path": str(d),
            "exists": d.exists(),
            "files": fcount,
            "size_mb": round(size_b / (1024 * 1024), 2),
        })
    return {
        "ok": True,
        "entries": entries,
        "total_files": total_files,
        "total_mb": round(total_bytes / (1024 * 1024), 2),
    }


def clean_shader_caches(extra_dirs: list[Path] | None = None) -> dict[str, Any]:
    """Safely purge stale shader cache files while skipping locked driver files."""
    scan = scan_shader_caches(extra_dirs=extra_dirs)
    removed_files = 0
    freed_bytes = 0
    locked_skipped = 0
    for entry in scan["entries"]:
        d = Path(entry["path"])
        if not d.exists():
            continue
        for p in list(d.rglob("*")):
            if p.is_file():
                try:
                    sz = p.stat().st_size
                    p.unlink()
                    removed_files += 1
                    freed_bytes += sz
                except OSError:
                    locked_skipped += 1
    return {
        "ok": True,
        "removed_files": removed_files,
        "freed_mb": round(freed_bytes / (1024 * 1024), 2),
        "locked_skipped": locked_skipped,
    }


def inspect_mpo_status() -> dict[str, Any]:
    """Check HKLM\\SOFTWARE\\Microsoft\\Windows\\Dwm\\OverlayTestMode (5 = MPO Disabled)."""
    key_path = r"SOFTWARE\Microsoft\Windows\Dwm"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
            val, _ = winreg.QueryValueEx(k, "OverlayTestMode")
            disabled = int(val) == 5
            return {"mpo_disabled": disabled, "registry_value": int(val), "status": "DISABLED (Stutter-Free)" if disabled else f"ENABLED (Value {val})"}
    except OSError:
        return {"mpo_disabled": False, "registry_value": None, "status": "ENABLED (Windows Default — Multi-Monitor Risk)"}


def toggle_mpo_fix(disable_mpo: bool = True, tweaks_dir: Path | None = None) -> dict[str, Any]:
    """Write safe MPO .reg tweak scripts and apply OverlayTestMode=5 if permissions allow (or guide UAC .reg run)."""
    tdir = tweaks_dir or (LOCAL_APP_ROOT / "tweaks")
    tdir.mkdir(parents=True, exist_ok=True)
    disable_reg = tdir / "disable_mpo_stutter_fix.reg"
    restore_reg = tdir / "restore_mpo_default.reg"
    disable_reg.write_text(
        "Windows Registry Editor Version 5.00\r\n\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Dwm]\r\n"
        '"OverlayTestMode"=dword:00000005\r\n',
        encoding="utf-16",
    )
    restore_reg.write_text(
        "Windows Registry Editor Version 5.00\r\n\r\n"
        "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Dwm]\r\n"
        '"OverlayTestMode"=-\r\n',
        encoding="utf-16",
    )
    direct_applied = False
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\Dwm", 0, winreg.KEY_SET_VALUE) as k:
            if disable_mpo:
                winreg.SetValueEx(k, "OverlayTestMode", 0, winreg.REG_DWORD, 5)
            else:
                try:
                    winreg.DeleteValue(k, "OverlayTestMode")
                except FileNotFoundError:
                    pass
        direct_applied = True
    except OSError:
        pass

    return {
        "ok": True,
        "direct_applied": direct_applied,
        "requires_uac_reg_merge": not direct_applied,
        "disable_reg_path": str(disable_reg),
        "restore_reg_path": str(restore_reg),
    }


def scan_active_overlay_processes() -> list[dict[str, str]]:
    """Detect running background overlay/hook tools that frequently conflict with DX12/DXVK games."""
    hits: list[dict[str, str]] = []
    try:
        out = subprocess.check_output(["tasklist", "/FO", "CSV", "/NH"], text=True, stderr=subprocess.DEVNULL)
        seen: set[str] = set()
        for line in out.splitlines():
            parts = [p.strip('"') for p in line.split(",")]
            if not parts:
                continue
            pname = parts[0].lower()
            if pname in KNOWN_CONFLICT_PROCESSES and pname not in seen:
                seen.add(pname)
                hits.append({"process": parts[0], "reason": KNOWN_CONFLICT_PROCESSES[pname]})
    except Exception:
        pass
    return hits


def scan_game_anticheat(game_dir: Path, max_depth: int = 3) -> dict[str, Any]:
    if not game_dir.exists() or not game_dir.is_dir():
        return {"ok": False, "safe_to_inject": False, "hits": [], "error": f"Folder not found: {game_dir}"}
    hits: list[dict[str, str]] = []
    seen: set[str] = set()
    base_parts = len(game_dir.resolve().parts)
    for root, dirs, files in os.walk(game_dir):
        if len(Path(root).resolve().parts) - base_parts >= max_depth:
            dirs[:] = []
        for item in dirs + files:
            low = item.lower()
            for sig, desc in ANTICHEAT_SIGNATURES.items():
                if sig in low and item not in seen:
                    seen.add(item)
                    hits.append({"item": item, "engine": desc})
    return {"ok": True, "safe_to_inject": len(hits) == 0, "hits": hits}


def get_official_dxvk_info() -> dict[str, str]:
    url = "https://github.com/doitsujin/dxvk/releases/download/v2.5.3/dxvk-2.5.3.tar.gz"
    tag = "v2.5.3"
    filename = "dxvk-2.5.3.tar.gz"
    try:
        req = urllib.request.Request(DXVK_RELEASES_API, headers={"User-Agent": "SI-Shader-Vulkan-Studio/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            rel = json.loads(resp.read().decode("utf-8"))
        tag = rel.get("tag_name") or tag
        for a in rel.get("assets", []):
            nm = a.get("name", "")
            if nm.startswith("dxvk-") and nm.endswith(".tar.gz") and "native" not in nm:
                url = a["browser_download_url"]
                filename = nm
                break
    except Exception:
        pass
    return {"tag": tag, "filename": filename, "url": url}


def install_dxvk_to_game(
    game_dir: Path,
    exe_rel_path: str | None = None,
    cache_dir: Path | None = None,
    force_download: bool = False,
) -> dict[str, Any]:
    """Download official doitsujin/dxvk .tar.gz, match exact x32/x64 DLLs to PE imports, and create SHA-256 backup."""
    ac = scan_game_anticheat(game_dir)
    if not ac.get("safe_to_inject"):
        return {"ok": False, "blocked_by_anticheat": True, "hits": ac.get("hits", []), "error": "Anti-Cheat detected! Blocked DXVK injection to prevent bans."}

    # Locate target EXE
    if exe_rel_path and (game_dir / exe_rel_path).exists():
        exe_path = game_dir / exe_rel_path
    else:
        exes = [p for p in game_dir.glob("*.exe") if not any(w in p.name.lower() for w in ("unins", "crash", "setup", "redist"))]
        if not exes:
            exes = list(game_dir.glob("*.exe"))
        if not exes:
            return {"ok": False, "error": f"No .exe found in {game_dir}"}
        exe_path = max(exes, key=lambda p: p.stat().st_size)

    pe = inspect_pe_binary(exe_path)
    if not pe.get("ok"):
        return pe
    if "d3d12.dll" in pe["dx_apis"] and not pe["dxvk_eligible"]:
        return {"ok": False, "error": f"{exe_path.name} is DirectX 12 native (use Shader Cache + MPO fixes instead of DXVK)."}

    cdir = cache_dir or (LOCAL_APP_ROOT / "cache")
    cdir.mkdir(parents=True, exist_ok=True)
    info = get_official_dxvk_info()
    tgz_path = cdir / info["filename"]

    if force_download or not tgz_path.exists() or not tarfile.is_tarfile(tgz_path):
        tmp_tgz = tgz_path.with_suffix(".tmp")
        req = urllib.request.Request(info["url"], headers={"User-Agent": "SI-Shader-Vulkan-Studio/1.0"})
        with urllib.request.urlopen(req, timeout=45) as resp, tmp_tgz.open("wb") as out:
            shutil.copyfileobj(resp, out, length=256 * 1024)
        tmp_tgz.replace(tgz_path)

    sub_arch = "x32" if pe["is_32bit"] else "x64"
    apis = pe["dx_apis"] or ["d3d11.dll", "dxgi.dll"]
    dlls_needed: set[str] = set()
    if "d3d9.dll" in apis:
        dlls_needed.add("d3d9.dll")
    if any(a in apis for a in ("d3d10.dll", "d3d10_1.dll", "d3d11.dll")):
        dlls_needed.update(("d3d11.dll", "dxgi.dll", "d3d10core.dll"))
    if not dlls_needed:
        dlls_needed.update(("d3d11.dll", "dxgi.dll"))

    target_dir = exe_path.parent
    backup_dir = target_dir / "si_shader_studio_backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = backup_dir / "manifest.json"
    if not manifest_path.exists():
        manifest: dict[str, Any] = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "exe_path": str(exe_path),
            "exe_sha256": sha256_file(exe_path),
            "existed_before": {},
            "created_by_studio": [],
        }
        shutil.copy2(exe_path, backup_dir / exe_path.name)
        for dll in dlls_needed | {"dxvk.conf"}:
            fp = target_dir / dll
            if fp.exists():
                shutil.copy2(fp, backup_dir / dll)
                manifest["existed_before"][dll] = sha256_file(fp)
    else:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    installed: list[str] = []
    with tarfile.open(tgz_path, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            if sub_arch in parts and Path(member.name).name.lower() in dlls_needed:
                dll_name = Path(member.name).name.lower()
                dst = target_dir / dll_name
                src_fh = tf.extractfile(member)
                assert src_fh is not None
                with src_fh, dst.open("wb") as out_fh:
                    shutil.copyfileobj(src_fh, out_fh)
                installed.append(dll_name)
                if dll_name not in manifest["existed_before"] and dll_name not in manifest["created_by_studio"]:
                    manifest["created_by_studio"].append(dll_name)

    # Write calibrated dxvk.conf for low-latency + async pipeline compiler threads
    threads = max(2, min(8, (os.cpu_count() or 4) // 2))
    conf_path = target_dir / "dxvk.conf"
    conf_path.write_text(
        "# Generated cleanly by SI-Shader-Vulkan-Studio\n"
        f"dxvk.numCompilerThreads = {threads}\n"
        "dxgi.maxFrameLatency = 1\n"
        "d3d9.maxFrameLatency = 1\n",
        encoding="utf-8",
    )
    if "dxvk.conf" not in manifest["existed_before"] and "dxvk.conf" not in manifest["created_by_studio"]:
        manifest["created_by_studio"].append("dxvk.conf")

    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {
        "ok": True,
        "dxvk_tag": info["tag"],
        "arch": sub_arch,
        "installed_dlls": sorted(installed),
        "compiler_threads": threads,
        "dxvk_conf": str(conf_path),
    }


def rollback_game_studio(target_dir: Path) -> dict[str, Any]:
    """Restore original EXE + overwritten files (SHA-256 verified) and remove injected DXVK DLLs."""
    backup_dir = target_dir / "si_shader_studio_backup"
    manifest_path = backup_dir / "manifest.json"
    if not manifest_path.exists():
        return {"ok": False, "error": "No SI-Shader-Vulkan-Studio backup found in this game folder."}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    restored: list[str] = []
    removed: list[str] = []

    exe_path = Path(manifest["exe_path"])
    bak_exe = backup_dir / exe_path.name
    if bak_exe.exists():
        shutil.copy2(bak_exe, exe_path)
        if sha256_file(exe_path) != manifest["exe_sha256"]:
            return {"ok": False, "error": f"SHA-256 verification failed restoring {exe_path.name}"}
        restored.append(exe_path.name)

    for dll, orig_hash in manifest.get("existed_before", {}).items():
        src = backup_dir / dll
        dst = target_dir / dll
        if src.exists():
            shutil.copy2(src, dst)
            if sha256_file(dst) != orig_hash:
                return {"ok": False, "error": f"SHA-256 verification failed restoring {dll}"}
            restored.append(dll)

    for created in manifest.get("created_by_studio", []):
        fp = target_dir / created
        if fp.exists():
            fp.unlink()
            removed.append(created)

    return {"ok": True, "restored": restored, "removed": removed}
