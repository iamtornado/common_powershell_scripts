# ===================================================================
# 系统信息查询工具 - System Information Query Tool
# 用途：自动获取Windows计算机的基本系统信息
# 适用场景：帮助员工快速获取电脑信息，便于IT运维人员进行故障诊断
# ===================================================================

param(
    [switch]$SaveToFile,
    [string]$OutputPath = "SystemInfo.txt"
)

# 设置控制台编码以正确显示中文
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 清屏并显示标题
Clear-Host
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "    系统信息查询工具" -ForegroundColor Yellow
Write-Host "  System Information Tool" -ForegroundColor Yellow
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

# 初始化输出内容
$outputContent = @()
$outputContent += "系统信息查询结果 - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$outputContent += "=" * 50

try {
    # 1. 获取计算机名（FQDN）
    Write-Host "正在获取计算机信息..." -ForegroundColor Green
    $computerName = $env:COMPUTERNAME
    $domain = $env:USERDOMAIN
    $fqdn = "$computerName.$domain"
    
    # 尝试获取完整的FQDN
    try {
        $fqdnFull = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
        if ($fqdnFull -and $fqdnFull -ne $computerName) {
            $fqdn = $fqdnFull
        }
    }
    catch {
        # 如果获取失败，使用基本的计算机名
    }
    
    Write-Host "计算机名 (FQDN): $fqdn" -ForegroundColor White
    $outputContent += "计算机名 (FQDN): $fqdn"
    
    # 2. 获取当前登录用户
    Write-Host "正在获取用户信息..." -ForegroundColor Green
    $currentUser = $env:USERNAME
    $userDomain = $env:USERDOMAIN
    $fullUserName = "$userDomain\$currentUser"
    
    Write-Host "当前登录用户: $fullUserName" -ForegroundColor White
    $outputContent += "当前登录用户: $fullUserName"
    $outputContent += ""
    
    # 3. 获取网络适配器信息（仅显示已连接且有IP地址的网卡）
    Write-Host "正在获取网络信息..." -ForegroundColor Green
    $outputContent += "网络适配器信息:"
    $outputContent += "-" * 30
    
    # 获取所有活动的网络适配器
    $networkAdapters = Get-NetAdapter | Where-Object { 
        $_.Status -eq "Up" -and 
        $_.Virtual -eq $false -and 
        $_.Name -notlike "*Loopback*" -and
        $_.Name -notlike "*Teredo*" -and
        $_.Name -notlike "*isatap*"
    }
    
    $adapterCount = 0
    foreach ($adapter in $networkAdapters) {
        # 获取该网卡的IP配置
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                   Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -ne "0.0.0.0" }
        
        if ($ipConfig) {
            $adapterCount++
            $adapterName = $adapter.Name
            $macAddress = $adapter.MacAddress
            $ipAddress = $ipConfig.IPAddress
            
            Write-Host ""
            Write-Host "网卡 $adapterCount - $adapterName" -ForegroundColor Yellow
            Write-Host "  IP地址: $ipAddress" -ForegroundColor White
            Write-Host "  MAC地址: $macAddress" -ForegroundColor White
            
            $outputContent += "网卡 $adapterCount - $adapterName"
            $outputContent += "  IP地址: $ipAddress"
            $outputContent += "  MAC地址: $macAddress"
            $outputContent += ""
        }
    }
    
    if ($adapterCount -eq 0) {
        Write-Host "未找到活动的网络连接" -ForegroundColor Red
        $outputContent += "未找到活动的网络连接"
    }
    
    # 4. 获取额外的系统信息
    Write-Host "正在获取系统详细信息..." -ForegroundColor Green
    $outputContent += "系统详细信息:"
    $outputContent += "-" * 30
    
    # 操作系统信息
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $osName = $osInfo.Caption
    $osVersion = $osInfo.Version
    $osArchitecture = $osInfo.OSArchitecture
    
    Write-Host ""
    Write-Host "操作系统: $osName" -ForegroundColor White
    Write-Host "系统版本: $osVersion" -ForegroundColor White
    Write-Host "系统架构: $osArchitecture" -ForegroundColor White
    
    $outputContent += "操作系统: $osName"
    $outputContent += "系统版本: $osVersion"
    $outputContent += "系统架构: $osArchitecture"
    
    # 计算机制造商和型号
    $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
    $manufacturer = $computerInfo.Manufacturer
    $model = $computerInfo.Model
    
    Write-Host "制造商: $manufacturer" -ForegroundColor White
    Write-Host "型号: $model" -ForegroundColor White
    
    $outputContent += "制造商: $manufacturer"
    $outputContent += "型号: $model"
    
    # 内存信息
    $totalMemoryGB = [math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)
    Write-Host "总内存: $totalMemoryGB GB" -ForegroundColor White
    $outputContent += "总内存: $totalMemoryGB GB"
    
}
catch {
    $errorMessage = "获取系统信息时发生错误: $($_.Exception.Message)"
    Write-Host $errorMessage -ForegroundColor Red
    $outputContent += $errorMessage
}

# 显示分隔线
Write-Host ""
Write-Host "=================================" -ForegroundColor Cyan

# 将所有信息复制到剪切板
try {
    $outputContent += ""
    $outputContent += "========================================"
    $outputContent += "以上信息已自动复制到剪切板"
    $outputContent += "请直接粘贴发送给IT工程师"
    $outputContent += "========================================"
    
    $clipboardContent = $outputContent -join "`r`n"
    $clipboardContent | Set-Clipboard
    
    Write-Host ""
    Write-Host "✅ 详细信息已自动复制到剪切板！" -ForegroundColor Green
    Write-Host "请直接在IM软件中粘贴发送给IT工程师" -ForegroundColor Yellow
}
catch {
    Write-Host "❌ 复制到剪切板失败: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "请手动复制以上信息" -ForegroundColor Yellow
}

# 保存到文件（如果指定了参数）
if ($SaveToFile) {
    try {
        $outputContent | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "信息已保存到文件: $OutputPath" -ForegroundColor Green
    }
    catch {
        Write-Host "保存文件时发生错误: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 提示用户
Write-Host ""
Write-Host "提示：" -ForegroundColor Yellow
Write-Host "1. 信息已自动复制到剪切板，可直接粘贴发送" -ForegroundColor White
Write-Host "2. 如需保存信息到文件，请运行: .\Get-SystemInfo.ps1 -SaveToFile" -ForegroundColor White
Write-Host "3. 按任意键退出..." -ForegroundColor White

# 等待用户按键
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")