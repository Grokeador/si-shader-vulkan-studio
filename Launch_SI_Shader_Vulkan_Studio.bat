@echo off
title SI-Shader-Vulkan-Studio — Global Game Stutter, MPO & DXVK Fixer
cd /d "%~dp0"
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.10+ not found. Opening official download page...
    start https://www.python.org/downloads/windows/
    pause
    exit /b 1
)
python si_shader_vulkan_studio.py web %*
if errorlevel 1 pause
