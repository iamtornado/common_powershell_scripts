@echo off
chcp 65001 >nul
title 自动设置高性能电源计划

:: 检查管理员权限，如果没有则自动提升
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [信息] 检测到需要管理员权限，正在自动提升...
    echo.
    
    :: 使用runas命令自动提升权限
    runas /user:administrator "%~f0" >nul 2>&1
    if %errorLevel% equ 0 (
        exit /b
    ) else (
        echo [错误] 无法自动提升权限！
        echo 请手动右键点击此脚本，选择"以管理员身份运行"
        echo.
        pause
        exit /b 1
    )
)

echo ========================================
echo     Windows电源计划自动设置工具
echo ========================================
echo.

:: 获取电源计划列表
echo [信息] 当前系统电源计划列表：
echo.
powercfg /list
echo.

echo [信息] 正在设置高性能电源计划...

:: 设置高性能电源计划（适用于所有Windows版本）
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >nul 2>&1
if %errorLevel% equ 0 (
    echo [成功] 已设置电源计划为"高性能"
    goto :verify
)

:: 如果设置失败，尝试创建新的高性能计划
echo [信息] 设置失败，尝试创建新的高性能计划...
powercfg /duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c "自定义高性能" >nul 2>&1
if %errorLevel% equ 0 (
    echo [成功] 已创建并设置自定义高性能电源计划
    goto :verify
)

echo [错误] 无法设置高性能电源计划！
echo 请手动检查系统电源计划设置
goto :end

:verify
echo.
echo [信息] 正在验证当前电源计划...
echo.

:: 显示当前活动电源计划
powercfg /getactivescheme
echo.
echo [信息] 电源计划设置完成！
echo.

:end
echo ========================================
echo 按任意键退出...
pause >nul
