# ===================================================================
# 基础系统信息查询工具 - Basic System Information Tool
# 用途：快速获取Windows计算机的核心信息
# 适用场景：员工快速查询电脑基本信息，提供给IT运维人员
# ===================================================================

# 设置控制台编码以正确显示中文
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 清屏并显示标题
Clear-Host
Write-Host "=============================" -ForegroundColor Cyan
Write-Host "  基础系统信息查询" -ForegroundColor Yellow
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

try {
    # 获取计算机名（FQDN）
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
        # 使用基本计算机名
    }
    
    Write-Host "计算机名: $fqdn" -ForegroundColor Green
    
    # 获取当前登录用户
    $currentUser = $env:USERNAME
    $userDomain = $env:USERDOMAIN
    $fullUserName = "$userDomain\$currentUser"
    Write-Host "当前用户: $fullUserName" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "网络信息:" -ForegroundColor Yellow
    Write-Host "---------" -ForegroundColor Yellow
    
    # 获取活动网络适配器的IP和MAC地址
    $networkAdapters = Get-NetAdapter | Where-Object { 
        $_.Status -eq "Up" -and 
        $_.Virtual -eq $false -and 
        $_.Name -notlike "*Loopback*" -and
        $_.Name -notlike "*Teredo*" -and
        $_.Name -notlike "*isatap*"
    }
    
    $foundActiveConnection = $false
    foreach ($adapter in $networkAdapters) {
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                   Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -ne "0.0.0.0" }
        
        if ($ipConfig) {
            $foundActiveConnection = $true
            $adapterName = $adapter.Name
            $macAddress = $adapter.MacAddress
            $ipAddress = $ipConfig.IPAddress
            
            Write-Host "网卡名称: $adapterName" -ForegroundColor White
            Write-Host "IP地址: $ipAddress" -ForegroundColor Green
            Write-Host "MAC地址: $macAddress" -ForegroundColor Green
            Write-Host ""
        }
    }
    
    if (-not $foundActiveConnection) {
        Write-Host "未找到活动的网络连接" -ForegroundColor Red
    }
    
}
catch {
    Write-Host "获取信息时发生错误: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "=============================" -ForegroundColor Cyan
Write-Host "请将以上信息提供给IT工程师" -ForegroundColor Yellow
Write-Host "按任意键退出..." -ForegroundColor White

# 等待用户按键
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")