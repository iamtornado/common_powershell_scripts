#Requires -Version 5.1

<#
.SYNOPSIS
    批量安装字体文件到Windows系统

.DESCRIPTION
    此脚本可以批量安装字体文件（.ttf、.ttc、.otf）到Windows系统字体目录。
    支持递归扫描指定文件夹中的所有字体文件，自动跳过已安装的字体。
    需要管理员权限运行。

.PARAMETER FontSourcePath
    字体源文件夹路径。默认值为 "D:\Myse_Fonts"

.EXAMPLE
    .\Install-Fonts.ps1
    使用默认路径 D:\Myse_Fonts 安装字体

.EXAMPLE
    .\Install-Fonts.ps1 -FontSourcePath "C:\Fonts"
    从指定路径 C:\Fonts 安装字体

.NOTES
    作者: Auto Generated
    需要管理员权限运行
    支持的字体格式: .ttf, .ttc, .otf
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$FontSourcePath = "D:\Myse_Fonts"
)

# 设置控制台输出编码为UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# 设置错误处理
$ErrorActionPreference = "Continue"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    字体批量安装工具" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 检查路径是否存在
if (-not (Test-Path -Path $FontSourcePath)) {
    Write-Warning "字体源路径不存在: $FontSourcePath"
    Write-Host "字体安装跳过" -ForegroundColor Yellow
    exit 1
}

# 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "安装字体需要管理员权限，当前未以管理员身份运行"
    Write-Host "请以管理员身份运行此脚本" -ForegroundColor Red
    Write-Host "字体安装跳过" -ForegroundColor Yellow
    exit 1
}

Write-Host "字体源路径: $FontSourcePath" -ForegroundColor Green
Write-Host ""

# 遍历字体文件夹中的所有字体文件
$fontFiles = Get-ChildItem -Path $FontSourcePath -Recurse -Include "*.ttf","*.ttc","*.otf" -ErrorAction SilentlyContinue

if ($null -eq $fontFiles -or $fontFiles.Count -eq 0) {
    Write-Warning "在指定路径中未找到字体文件（.ttf, .ttc, .otf）"
    Write-Host "字体安装跳过" -ForegroundColor Yellow
    exit 1
}

$totalFonts = $fontFiles.Count
$installedCount = 0
$skippedCount = 0
$failedCount = 0

Write-Host "找到 $totalFonts 个字体文件，开始安装..." -ForegroundColor Green
Write-Host ""

$fontFiles | ForEach-Object {
    try {
        $fontName = $_.Name
        $fontExtension = $_.Extension.ToLower()
        $fontPath = "C:\Windows\Fonts\$fontName"
        
        # 根据字体类型确定注册表后缀
        $registrySuffix = switch ($fontExtension) {
            ".ttf" { " (TrueType)" }
            ".ttc" { " (TrueType)" }
            ".otf" { " (OpenType)" }
            default { " (TrueType)" }
        }
        
        # 构建注册表项名称
        $registryName = $fontName -replace [regex]::Escape($_.Extension), $registrySuffix
        
        # 检查字体文件是否已存在
        $existingFont = Get-ChildItem -Path "C:\Windows\Fonts" -Filter $fontName -ErrorAction SilentlyContinue
        
        # 检查注册表中是否已注册
        $registryFont = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" `
            -Name $registryName -ErrorAction SilentlyContinue
        
        # 如果文件存在且注册表中也已注册，则跳过
        if ($existingFont -and $registryFont) {
            $skippedCount++
            Write-Host "字体已存在且已注册，跳过: $fontName" -ForegroundColor Yellow
        }
        # 如果文件不存在或注册表中未注册，则需要安装/修复
        else {
            Write-Host "正在安装字体: $fontName" -NoNewline
            
            # 直接使用 Copy-Item（同步操作，速度快）
            try {
                # 如果文件不存在，则复制文件
                if (-not $existingFont) {
                    Copy-Item -Path $_.FullName -Destination $fontPath -Force -ErrorAction Stop
                }
                
                # 如果注册表中不存在，则创建注册表项
                if (-not $registryFont) {
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" `
                        -Name $registryName `
                        -Value $fontName `
                        -PropertyType String `
                        -Force `
                        -ErrorAction Stop | Out-Null
                }
                
                $installedCount++
                Write-Host " - 成功" -ForegroundColor Green
            }
            catch {
                $failedCount++
                Write-Host " - 失败: $($_.Exception.Message)" -ForegroundColor Red
                Write-Warning "安装字体失败: $fontName - $($_.Exception.Message)"
            }
        }
    }
    catch {
        $failedCount++
        Write-Warning "处理字体时出错: $fontName - $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "字体安装完成" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "已安装: $installedCount" -ForegroundColor Green
Write-Host "已跳过: $skippedCount" -ForegroundColor Yellow
if ($failedCount -gt 0) {
    Write-Host "失败: $failedCount" -ForegroundColor Red
}
Write-Host "总计: $totalFonts" -ForegroundColor Cyan
Write-Host ""


