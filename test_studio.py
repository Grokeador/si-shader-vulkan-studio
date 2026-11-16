"""Automated verification suite for SI-Shader-Vulkan-Studio."""

import io
import json
import shutil
import struct
import tarfile
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from si_shader_vulkan_studio import apply_selected_optimizations, start_web_server
from vulkan_pe_engine import (
    apply_4gb_laa_patch,
    clean_shader_caches,
    inspect_pe_binary,
    install_dxvk_to_game,
    rollback_game_studio,
    scan_shader_caches,
    sha256_file,
    toggle_mpo_fix,
)


def _make_minimal_pe32_exe(with_laa: bool = False, import_dll: bytes = b"d3d9.dll") -> bytes:
    """Build a valid minimal PE32 (x86 32-bit) executable with an Import Table entry."""
    buf = bytearray(0x600)
    buf[0:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_off)
    buf[pe_off : pe_off + 4] = b"PE\x00\x00"
    chars = 0x0102 | (0x0020 if with_laa else 0)
    # Machine=0x014C (x86), NumSections=1, SizeOfOptionalHeader=0xE0 (224), Characteristics
    struct.pack_into("<HHIIIHH", buf, pe_off + 4, 0x014C, 1, 0, 0, 0, 0xE0, chars)
    opt_off = pe_off + 24
    struct.pack_into("<H", buf, opt_off, 0x010B)  # PE32 magic
    # Import Directory entry inside DataDirectory[1] -> opt_off + 104
    struct.pack_into("<II", buf, opt_off + 104, 0x1000, 40)
    # Single section mapped VA=0x1000..0x1600, raw=0x200..0x600
    sec_off = opt_off + 0xE0
    struct.pack_into("<8sIIII", buf, sec_off, b".rdata\x00\x00", 0x400, 0x1000, 0x400, 0x200)
    # Import Descriptor at raw 0x200 (VA 0x1000): Name RVA = 0x1100 (raw 0x300)
    struct.pack_into("<IIIII", buf, 0x200, 0x1050, 0, 0, 0x1100, 0x1060)
    buf[0x300 : 0x300 + len(import_dll)] = import_dll
    return bytes(buf)


class SiShaderVulkanStudioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="si_shader_studio_"))
        self.game_dir = self.tmp / "ClassicDX9Game"
        self.game_dir.mkdir()
        self.exe_path = self.game_dir / "ClassicGame.exe"
        self.exe_path.write_bytes(_make_minimal_pe32_exe(with_laa=False, import_dll=b"d3d9.dll"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pe_inspection_and_4gb_laa_patch_and_rollback(self) -> None:
        pe_before = inspect_pe_binary(self.exe_path)
        self.assertTrue(pe_before["ok"])
        self.assertTrue(pe_before["is_32bit"])
        self.assertFalse(pe_before["laa_4gb_enabled"])
        self.assertTrue(pe_before["needs_4gb_patch"])
        self.assertIn("d3d9.dll", pe_before["dx_apis"])
        self.assertTrue(pe_before["dxvk_eligible"])

        orig_sha = sha256_file(self.exe_path)
        res = apply_selected_optimizations(
            self.game_dir,
            options={"clean_shader_cache": False, "disable_mpo_stutter": False, "install_dxvk": False, "patch_4gb_laa": True},
        )
        self.assertTrue(res["ok"])
        self.assertTrue(res["steps"]["laa_4gb"]["patched"])
        pe_after = inspect_pe_binary(self.exe_path)
        self.assertTrue(pe_after["laa_4gb_enabled"])
        self.assertFalse(pe_after["needs_4gb_patch"])

        rb = rollback_game_studio(self.game_dir)
        self.assertTrue(rb["ok"])
        self.assertEqual(sha256_file(self.exe_path), orig_sha)

    def test_dxvk_install_matches_x32_d3d9_and_anticheat_blocks(self) -> None:
        cache_dir = self.tmp / "dxvk_cache"
        cache_dir.mkdir()
        tgz = cache_dir / "dxvk-2.5.3.tar.gz"
        with tarfile.open(tgz, "w:gz") as tf:
            for arc, content in (
                ("dxvk-2.5.3/x32/d3d9.dll", b"DXVK32_D3D9"),
                ("dxvk-2.5.3/x64/d3d9.dll", b"DXVK64_D3D9"),
                ("dxvk-2.5.3/x32/d3d11.dll", b"DXVK32_D3D11"),
            ):
                ti = tarfile.TarInfo(arc)
                ti.size = len(content)
                tf.addfile(ti, io.BytesIO(content))

        with mock.patch(
            "vulkan_pe_engine.get_official_dxvk_info",
            return_value={"tag": "v2.5.3", "filename": "dxvk-2.5.3.tar.gz", "url": "https://example.invalid/dxvk.tar.gz"},
        ):
            res = install_dxvk_to_game(self.game_dir, cache_dir=cache_dir)
        self.assertTrue(res["ok"])
        self.assertEqual(res["arch"], "x32")
        self.assertEqual(res["installed_dlls"], ["d3d9.dll"])
        self.assertEqual((self.game_dir / "d3d9.dll").read_bytes(), b"DXVK32_D3D9")
        self.assertTrue((self.game_dir / "dxvk.conf").exists())

        # Anti-cheat blocks any online game injection
        (self.game_dir / "BattlEye").mkdir()
        (self.game_dir / "BattlEye" / "BEService_x64.exe").write_bytes(b"MZ")
        blocked = install_dxvk_to_game(self.game_dir, cache_dir=cache_dir)
        self.assertFalse(blocked["ok"])
        self.assertTrue(blocked.get("blocked_by_anticheat"))

        # Clean rollback removes created dxvk files cleanly
        rb = rollback_game_studio(self.game_dir)
        self.assertTrue(rb["ok"])
        self.assertFalse((self.game_dir / "d3d9.dll").exists())
        self.assertFalse((self.game_dir / "dxvk.conf").exists())

    def test_shader_cache_clean_mpo_reg_and_web_server(self) -> None:
        mock_cache = self.tmp / "NVIDIA_DXCache"
        mock_cache.mkdir()
        (mock_cache / "old_shader_0.bin").write_bytes(b"\x01" * (1024 * 1024))
        s = scan_shader_caches(extra_dirs=[mock_cache])
        self.assertEqual(s["total_files"], 1)
        self.assertGreaterEqual(s["total_mb"], 0.9)
        cl = clean_shader_caches(extra_dirs=[mock_cache])
        self.assertEqual(cl["removed_files"], 1)

        tweak_out = self.tmp / "tweaks"
        mpo = toggle_mpo_fix(disable_mpo=True, tweaks_dir=tweak_out)
        self.assertTrue(mpo["ok"])
        self.assertTrue(Path(mpo["disable_reg_path"]).exists())
        self.assertTrue(Path(mpo["restore_reg_path"]).exists())

        srv = start_web_server(self.game_dir, port=0)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            for ep in ("/", "/api/state"):
                with urllib.request.urlopen(f"http://127.0.0.1:{port}{ep}", timeout=5) as r:
                    self.assertEqual(r.status, 200)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
