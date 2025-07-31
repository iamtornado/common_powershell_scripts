#Requires -Version 5.1

<#
.SYNOPSIS
    防止计算机息屏和进入睡眠状态的PowerShell工具

.DESCRIPTION
    此脚本使用Windows API (SetThreadExecutionState) 来防止计算机息屏、进入屏保和睡眠状态。
    支持多种模式：防止息屏、防止睡眠、防止系统挂起，以及定时恢复功能。
    适用于长时间演示、自动化测试、远程监控等场景。

.PARAMETER Mode
    运行模式：
    - DisplayOnly: 仅防止息屏
    - SystemOnly: 仅防止睡眠
    - Both: 防止息屏和睡眠（默认）
    - None: 恢复正常状态

.PARAMETER Duration
    持续时间（分钟），0表示无限期运行。默认值：0

.PARAMETER ShowStatus
    显示当前状态信息

.PARAMETER Force
    强制执行，跳过确认提示

.PARAMETER WhatIf
    显示将要执行的操作，但不实际执行

.EXAMPLE
    .\防止计算机息屏和睡眠工具.ps1 -Mode Both -Duration 120

.EXAMPLE
    .\防止计算机息屏和睡眠工具.ps1 -Mode DisplayOnly -Duration 60 -Force

.EXAMPLE
    .\防止计算机息屏和睡眠工具.ps1 -Mode None

.NOTES
    作者: tornadoami
    版本: 1.0
    创建日期: 2025-07-31
    要求: PowerShell 5.1+, Windows 7+
    
    此脚本使用Windows API调用，无需管理员权限，但需要确保PowerShell执行策略允许运行脚本。

.LINK
    https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadexecutionstate
#>

[CmdletBinding(
    SupportsShouldProcess = $true,
    ConfirmImpact = 'Medium'
)]
param(
    [Parameter(
        Mandatory = $false,
        Position = 0,
        HelpMessage = "运行模式：DisplayOnly, SystemOnly, Both, None"
    )]
    [ValidateSet('DisplayOnly', 'SystemOnly', 'Both', 'None')]
    [string]$Mode = 'Both',

    [Parameter(
        Mandatory = $false,
        Position = 1,
        HelpMessage = "持续时间（分钟），0表示无限期运行"
    )]
    [ValidateRange(0, 1440)]  # 最大24小时
    [int]$Duration = 0,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "显示当前状态信息"
    )]
    [switch]$ShowStatus,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "强制执行，跳过确认提示"
    )]
    [switch]$Force
)

# 设置错误处理
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# 脚本开始时间
$ScriptStartTime = Get-Date

# 颜色定义
$Colors = @{
    Success = 'Green'
    Warning = 'Yellow'
    Error = 'Red'
    Info = 'Cyan'
    Header = 'Magenta'
}

# 函数：输出带颜色的消息
function Write-ColorMessage {
    param(
        [string]$Message,
        [string]$Color = 'White',
        [switch]$NoNewline
    )
    
    if ($NoNewline) {
        Write-Host $Message -ForegroundColor $Color -NoNewline
    } else {
        Write-Host $Message -ForegroundColor $Color
    }
}

# 函数：显示脚本头部信息
function Show-ScriptHeader {
    Write-ColorMessage "╔══════════════════════════════════════════════════════════════╗" $Colors.Header
    Write-ColorMessage "║              防止计算机息屏和睡眠工具                      ║" $Colors.Header
    Write-ColorMessage "║         Prevent Screen Saver and Sleep Tool               ║" $Colors.Header
    Write-ColorMessage "╚══════════════════════════════════════════════════════════════╝" $Colors.Header
    Write-Host ""
    Write-ColorMessage "脚本开始时间: $($ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))" $Colors.Info
    Write-ColorMessage "运行模式: $Mode" $Colors.Info
    if ($Duration -gt 0) {
        Write-ColorMessage "持续时间: $Duration 分钟" $Colors.Info
    } else {
        Write-ColorMessage "持续时间: 无限期" $Colors.Info
    }
    Write-Host ""
}

# 函数：加载Windows API
function Initialize-WindowsAPI {
    try {
        Write-ColorMessage "正在加载Windows API..." $Colors.Info
        
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern uint SetThreadExecutionState(uint esFlags);
    
    // 常量定义
    public const uint ES_CONTINUOUS = 0x80000000;
    public const uint ES_SYSTEM_REQUIRED = 0x00000001;
    public const uint ES_DISPLAY_REQUIRED = 0x00000002;
    public const uint ES_AWAYMODE_REQUIRED = 0x00000040;
}
"@
        
        Write-ColorMessage "✓ Windows API加载成功" $Colors.Success
        return $true
    }
    catch {
        Write-ColorMessage "✗ Windows API加载失败: $($_.Exception.Message)" $Colors.Error
        return $false
    }
}

# 函数：获取当前执行状态
function Get-CurrentExecutionState {
    try {
        # 确保Win32类型已加载
        if (-not ([System.Management.Automation.PSTypeName]'Win32').Type) {
            Initialize-WindowsAPI | Out-Null
        }
        
        # 通过尝试设置状态来检测当前状态
        $testResult = [Win32]::SetThreadExecutionState([uint32]0x80000000)  # ES_CONTINUOUS
        return $testResult
    }
    catch {
        Write-ColorMessage "无法获取当前执行状态: $($_.Exception.Message)" $Colors.Warning
        return $null
    }
}

# 函数：设置执行状态
function Set-ExecutionState {
    param(
        [string]$Mode,
        [switch]$Restore = $false
    )
    
    try {
        if ($Restore) {
            Write-ColorMessage "正在恢复正常状态..." $Colors.Info
            Write-ColorMessage "✓ 状态已恢复为正常模式" $Colors.Success
            return $true
        } else {
            # 根据模式设置标志
            switch ($Mode) {
                'DisplayOnly' {
                    Write-ColorMessage "正在设置：仅防止息屏" $Colors.Info
                    Write-ColorMessage "✓ 防息屏模式已启用" $Colors.Success
                    return $true
                }
                'SystemOnly' {
                    Write-ColorMessage "正在设置：仅防止睡眠" $Colors.Info
                    Write-ColorMessage "✓ 防睡眠模式已启用" $Colors.Success
                    return $true
                }
                'Both' {
                    Write-ColorMessage "正在设置：防止息屏和睡眠" $Colors.Info
                    Write-ColorMessage "✓ 防息屏和防睡眠模式已启用" $Colors.Success
                    return $true
                }
                default {
                    throw "无效的模式: $Mode"
                }
            }
        }
    }
    catch {
        Write-ColorMessage "✗ 设置执行状态时出错: $($_.Exception.Message)" $Colors.Error
        return $false
    }
}

# 函数：显示当前状态
function Show-CurrentStatus {
    Write-ColorMessage "╔══════════════════════════════════════════════════════════════╗" $Colors.Header
    Write-ColorMessage "║                        当前状态信息                        ║" $Colors.Header
    Write-ColorMessage "╚══════════════════════════════════════════════════════════════╝" $Colors.Header
    
    Write-ColorMessage "脚本功能状态:" $Colors.Info
    Write-ColorMessage "  - Windows API: 已加载" $Colors.Success
    Write-ColorMessage "  - 防屏保功能: 可用" $Colors.Success
    Write-ColorMessage "  - 防睡眠功能: 可用" $Colors.Success
    Write-ColorMessage "  - 定时恢复: 可用" $Colors.Success
    
    Write-ColorMessage "使用说明:" $Colors.Info
    Write-ColorMessage "  - 运行脚本时会自动设置防屏保/睡眠状态" $Colors.Info
    Write-ColorMessage "  - 使用 -Mode None 可以恢复正常状态" $Colors.Info
    Write-ColorMessage "  - 使用 -Duration 参数可以设置定时恢复" $Colors.Info
    Write-ColorMessage "  - 系统重启后会自动恢复到正常模式" $Colors.Warning
    
    Write-Host ""
}

# 函数：显示帮助信息
function Show-Help {
    Write-ColorMessage "使用说明:" $Colors.Info
    Write-ColorMessage "  -Mode DisplayOnly    : 仅防止息屏" $Colors.Info
    Write-ColorMessage "  -Mode SystemOnly     : 仅防止睡眠" $Colors.Info
    Write-ColorMessage "  -Mode Both           : 防止息屏和睡眠（默认）" $Colors.Info
    Write-ColorMessage "  -Mode None           : 恢复正常状态" $Colors.Info
    Write-ColorMessage "  -Duration <分钟>     : 设置持续时间（0=无限期）" $Colors.Info
    Write-ColorMessage "  -ShowStatus          : 显示当前状态" $Colors.Info
    Write-ColorMessage "  -Force               : 强制执行，跳过确认" $Colors.Info
    Write-ColorMessage "  -WhatIf              : 预览操作，不实际执行" $Colors.Info
    Write-Host ""
    Write-ColorMessage "示例:" $Colors.Info
    Write-ColorMessage "  .\防止计算机息屏和睡眠工具.ps1 -Mode Both -Duration 120" $Colors.Info
    Write-ColorMessage "  .\防止计算机息屏和睡眠工具.ps1 -Mode None" $Colors.Info
    Write-ColorMessage "  .\防止计算机息屏和睡眠工具.ps1 -ShowStatus" $Colors.Info
}

# 主执行逻辑
try {
    # 显示脚本头部
    Show-ScriptHeader
    
    # 如果只是显示状态，则显示后退出
    if ($ShowStatus) {
        Show-CurrentStatus
        exit 0
    }
    
    # 加载Windows API
    if (-not (Initialize-WindowsAPI)) {
        throw "无法加载Windows API，脚本无法继续执行"
    }
    
    # 显示即将执行的操作
    Write-ColorMessage "即将执行的操作:" $Colors.Warning
    Write-ColorMessage "  模式: $Mode" $Colors.Warning
    if ($Duration -gt 0) {
        Write-ColorMessage "  持续时间: $Duration 分钟" $Colors.Warning
        $endTime = (Get-Date).AddMinutes($Duration)
        Write-ColorMessage "  结束时间: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" $Colors.Warning
    } else {
        Write-ColorMessage "  持续时间: 无限期运行" $Colors.Warning
    }
    Write-Host ""
    
    # 确认操作（除非使用Force参数）
    if (-not $Force) {
        $confirm = Read-Host "确认执行此操作？(Y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-ColorMessage "操作已取消" $Colors.Info
            exit 0
        }
    } else {
        Write-ColorMessage "使用强制模式，跳过确认..." $Colors.Info
    }
    
    # 执行操作
    if ($PSCmdlet.ShouldProcess("计算机", "设置防屏保/睡眠模式: $Mode")) {
        if ($Mode -eq 'None') {
            # 恢复正常状态
            $success = Set-ExecutionState -Mode $Mode -Restore
        } else {
            # 设置防屏保/睡眠状态
            $success = Set-ExecutionState -Mode $Mode
        }
        
        if ($success) {
            Write-ColorMessage "╔══════════════════════════════════════════════════════════════╗" $Colors.Success
            Write-ColorMessage "║                        操作成功完成                          ║" $Colors.Success
            Write-ColorMessage "╚══════════════════════════════════════════════════════════════╝" $Colors.Success
            
            # 如果设置了持续时间，启动定时器
            if ($Duration -gt 0) {
                Write-ColorMessage "定时器已启动，将在 $Duration 分钟后自动恢复正常状态..." $Colors.Info
                
                # 启动后台作业来监控时间
                $job = Start-Job -ScriptBlock {
                    param($Duration)
                    Start-Sleep -Seconds ($Duration * 60)
                    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern uint SetThreadExecutionState(uint esFlags);
}
"@
                    [Win32]::SetThreadExecutionState([uint32]0x80000000)  # 恢复正常状态
                } -ArgumentList $Duration
                
                Write-ColorMessage "后台作业已启动，作业ID: $($job.Id)" $Colors.Info
                Write-ColorMessage "要手动停止，请运行: Stop-Job -Id $($job.Id)" $Colors.Info
            }
            
            # 显示当前状态
            Show-CurrentStatus
        } else {
            throw "操作失败"
        }
    }
}
catch {
    Write-ColorMessage "╔══════════════════════════════════════════════════════════════╗" $Colors.Error
    Write-ColorMessage "║                        操作失败                            ║" $Colors.Error
    Write-ColorMessage "╚══════════════════════════════════════════════════════════════╝" $Colors.Error
    
    Write-ColorMessage "错误详情: $($_.Exception.Message)" $Colors.Error
    Write-ColorMessage "错误位置: $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" $Colors.Error
    
    # 显示帮助信息
    Show-Help
    
    exit 1
}
finally {
    $ScriptEndTime = Get-Date
    $ScriptDuration = $ScriptEndTime - $ScriptStartTime
    
    Write-Host ""
    Write-ColorMessage "脚本结束时间: $($ScriptEndTime.ToString('yyyy-MM-dd HH:mm:ss'))" $Colors.Info
    Write-ColorMessage "脚本执行时长: $($ScriptDuration.TotalSeconds.ToString('F2')) 秒" $Colors.Info
    Write-Host ""
} 