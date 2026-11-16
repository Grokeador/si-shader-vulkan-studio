# SI-Shader-Vulkan-Studio

Universal **1-Click Windows Shader Cache Cleaner, Multi-Monitor MPO Stutter Fixer, 32-bit 4GB LAA Binary Patcher & Official DXVK (DirectX -> Vulkan) Studio** for **any PC game** on Steam, Epic Games, Xbox/Game Pass, or GOG.

## Real Global Windows Gaming Problems Fixed

| Fix Module | Universal PC Gaming Pain Point | SI-Shader-Vulkan-Studio 1-Click Solution |
| --- | --- | --- |
| **1. Driver Shader Cache Doctor** | Corrupted / bloated NVIDIA DXCache, AMD DxCache & Windows D3DSCache cause sudden `0.1% low` stutter after driver/Windows updates | Scans exact MB across all driver caches and purges stale shader blobs safely (skipping locked files cleanly) |
| **2. Multi-Monitor MPO Stutter Fix** | Windows 11 Multiplane Overlay (MPO) causes flicker & stutter on dual-monitor setups (`144Hz + 60Hz` / Chromium / Discord) | Detects live `OverlayTestMode`, generates 1-click `.reg` disable & restore scripts (and applies directly when elevated) |
| **3. PE-Matched Official DXVK Installer** | Single-threaded DX9/DX10/DX11 PC classics stutter badly; copying wrong x32/x64 DLLs or `d3d12` breaks games | Parses PE binary headers + Import Tables (`d3d9.dll` / `d3d11.dll`), downloads official `doitsujin/dxvk`, writes calibrated `dxvk.conf`, and blocks Anti-Cheat games |
| **4. 32-bit 4GB LAA PE Patcher** | Classic 32-bit Windows games crash with Out-Of-Memory at `2 GB` RAM | Flips `IMAGE_FILE_LARGE_ADDRESS_AWARE` (`0x0020`) in the PE header, recomputes the Win32 `imagehlp` checksum, and saves a SHA-256 backup |
| **5. Active Overlay Conflict Guard** | Running hooks like RTSS, MSI Afterburner, Medal, Game Bar, or Discord overlay cause silent crashes & frame hitches | Scans live processes and flags conflicting hooks before launching games |

## Quick Start

Double-click **`Launch_SI_Shader_Vulkan_Studio.bat`** or run:

```powershell
# Launch 1-Click Dark Desktop UI
python si_shader_vulkan_studio.py web

# Native Desktop Window (no browser needed)
python si_shader_vulkan_studio.py tk

# Clean System Shader Caches Only
python si_shader_vulkan_studio.py clean-cache

# Restore Original Game EXE & Remove Injected DXVK (SHA-256 Verified)
python si_shader_vulkan_studio.py rollback --game-dir "C:\Path\To\Game"
```

## Automated Tests

```powershell
python -m unittest test_studio.py -v
```
