@echo off
chcp 65001 >nul
title 系统信息查询工具

echo.
echo ====================================
echo          系统信息查询工具
echo ====================================
echo.
echo 请选择要运行的脚本：
echo.
echo 1. 基础信息查询 (推荐) - 快速获取核心信息
echo 2. 详细信息查询 - 获取完整系统信息
echo 3. 详细信息查询并保存到文件
echo 4. 退出
echo.
set /p choice=请输入选择 (1-4): 

if "%choice%"=="1" (
    echo.
    echo 正在运行基础信息查询...
    powershell.exe -ExecutionPolicy Bypass -File "Get-BasicInfo.ps1"
    goto end
)

if "%choice%"=="2" (
    echo.
    echo 正在运行详细信息查询...
    powershell.exe -ExecutionPolicy Bypass -File "Get-SystemInfo.ps1"
    goto end
)

if "%choice%"=="3" (
    echo.
    echo 正在运行详细信息查询并保存到文件...
    powershell.exe -ExecutionPolicy Bypass -File "Get-SystemInfo.ps1" -SaveToFile
    echo.
    echo 信息已保存到 SystemInfo.txt 文件中
    goto end
)

if "%choice%"=="4" (
    echo 再见！
    goto end
)

echo 无效的选择，请重新运行程序。
pause

:end
echo.
echo 程序执行完毕。
pause