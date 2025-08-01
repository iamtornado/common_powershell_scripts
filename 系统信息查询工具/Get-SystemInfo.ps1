#Requires -Version 5.1

<#
.SYNOPSIS
    系统信息查询工具 - 支持本地和远程Windows计算机系统信息查询

.DESCRIPTION
    此脚本能够获取本地或远程Windows计算机的详细系统信息，包括计算机名、用户信息、
    网络配置、系统详情等。支持多种远程连接方式（WinRM优先，DCOM/WMI备用）。

.PARAMETER ComputerName
    目标计算机名称或IP地址。如果不指定，则查询本地计算机。

.PARAMETER Credential
    用于连接远程计算机的凭据。如果不提供，则使用当前用户凭据。

.PARAMETER SaveToFile
    是否将结果保存到文件

.PARAMETER OutputPath
    输出文件路径，默认为 "SystemInfo.txt"

.PARAMETER Force
    强制执行，跳过确认提示

.PARAMETER Timeout
    远程连接超时时间（秒），默认为30秒

.PARAMETER UseWinRM
    强制尝试使用WinRM连接。默认情况下直接使用WMI连接以提高速度。

.PARAMETER OutputDebug
    输出详细的调试信息，便于故障排查和性能分析。

.EXAMPLE
    .\Get-SystemInfo.ps1
    查询本地计算机信息

.EXAMPLE
    .\Get-SystemInfo.ps1 -ComputerName "SERVER01"
    查询远程计算机SERVER01的信息

.EXAMPLE
    .\Get-SystemInfo.ps1 -ComputerName "192.168.1.100" -Credential (Get-Credential)
    使用指定凭据查询远程计算机信息

.EXAMPLE
    .\Get-SystemInfo.ps1 -ComputerName "SERVER01" -SaveToFile -OutputPath "Server01_Info.txt"
    查询远程计算机并保存到指定文件

.EXAMPLE
    .\Get-SystemInfo.ps1 -ComputerName "SERVER01" -UseWinRM
    强制使用WinRM连接查询远程计算机（默认使用更快的WMI连接）

.EXAMPLE
    .\Get-SystemInfo.ps1 -ComputerName "10.65.37.46"
    查询远程计算机信息

.EXAMPLE
    .\Get-SystemInfo.ps1 -ComputerName "IMZSPC1097" -OutputDebug
    查询远程计算机并输出详细调试信息，便于故障排查

.NOTES
    作者: tornadoami
    版本: 2.9
    创建日期: 2025-08-01
    要求: PowerShell 5.1+, Windows 7+
    
    远程连接优先级：
    1. WinRM (Windows Remote Management) - 优先选择
    2. DCOM/WMI (Distributed COM) - 备用方案
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$ComputerName,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [switch]$SaveToFile,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "SystemInfo.txt",

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 300)]
    [int]$Timeout = 30,

    [Parameter(Mandatory = $false)]
    [switch]$UseWinRM,

    [Parameter(Mandatory = $false)]
    [switch]$OutputDebug
)

# 设置错误处理
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# 设置控制台编码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 脚本开始时间
$ScriptStartTime = Get-Date

# 判断是否为远程查询
$IsRemoteQuery = -not [string]::IsNullOrWhiteSpace($ComputerName)
$TargetComputer = if ($IsRemoteQuery) { $ComputerName } else { $env:COMPUTERNAME }

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
        [string]$Color = 'White'
    )
    Write-Host $Message -ForegroundColor $Color
}

# 函数：输出调试信息
function Write-DebugMessage {
    param(
        [string]$Message,
        [string]$Category = "DEBUG"
    )
    if ($OutputDebug) {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
        Write-Host "[$timestamp] [$Category] $Message" -ForegroundColor Cyan
    }
}

function Test-IsRealUser {
    param(
        [string]$UserName,
        [string]$UserDomain
    )
    
    # 排除系统虚拟账户
    $systemAccounts = @(
        'DWM-\d+',           # Desktop Window Manager
        'UMFD-\d+',          # User Mode Font Driver
        'SYSTEM',            # System account
        'LOCAL SERVICE',     # Local Service
        'NETWORK SERVICE',   # Network Service
        'ANONYMOUS LOGON',   # Anonymous
        'IUSR',             # IIS User
        'IWAM_.*',          # IIS Web Application Manager
        'ASPNET',           # ASP.NET account
        'DefaultAccount',    # Windows 10 default account
        'WDAGUtilityAccount' # Windows Defender Application Guard
    )
    
    # 排除系统域
    $systemDomains = @(
        'Window Manager',
        'Font Driver Host',
        'NT AUTHORITY',
        'BUILTIN'
    )
    
    # 检查用户名是否为系统账户
    foreach ($pattern in $systemAccounts) {
        if ($UserName -match "^$pattern$") {
            return $false
        }
    }
    
    # 检查域名是否为系统域
    if ($UserDomain -in $systemDomains) {
        return $false
    }
    
    return $true
}

# 函数：测试网络连通性
function Test-NetworkConnectivity {
    param([string]$TargetComputer)
    
    Write-ColorMessage "正在检测网络连通性..." $Colors.Info
    Write-DebugMessage "开始ping测试目标: $TargetComputer" "NETWORK"
    
    try {
        $startTime = Get-Date
        
        # 检查是否为IP地址
        $isIPAddress = $false
        try {
            [System.Net.IPAddress]::Parse($TargetComputer) | Out-Null
            $isIPAddress = $true
            Write-DebugMessage "目标是IP地址: $TargetComputer" "NETWORK"
        }
        catch {
            $isIPAddress = $false
            Write-DebugMessage "目标是主机名: $TargetComputer" "NETWORK"
            
            # 如果是主机名，尝试DNS解析
            try {
                Write-DebugMessage "开始DNS解析..." "DNS"
                $dnsResult = Resolve-DnsName -Name $TargetComputer -ErrorAction SilentlyContinue
                if ($dnsResult) {
                    $resolvedIP = $dnsResult | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1 -ExpandProperty IPAddress
                    Write-DebugMessage "DNS解析成功: $TargetComputer -> $resolvedIP" "DNS"
                } else {
                    Write-DebugMessage "DNS解析失败: 无法解析 $TargetComputer" "DNS"
                }
            }
            catch {
                Write-DebugMessage "DNS解析异常: $($_.Exception.Message)" "DNS"
            }
        }
        
        $pingResult = Test-Connection -ComputerName $TargetComputer -Count 1 -Quiet -ErrorAction SilentlyContinue
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalMilliseconds
        
        Write-DebugMessage "Ping测试耗时: $($duration.ToString('F2'))ms" "NETWORK"
        
        if ($pingResult) {
            Write-ColorMessage "✓ 网络连通性检测成功" $Colors.Success
            Write-DebugMessage "网络连通性测试成功" "NETWORK"
            return $true
        } else {
            Write-ColorMessage "✗ 网络连通性检测失败" $Colors.Error
            Write-DebugMessage "网络连通性测试失败" "NETWORK"
            return $false
        }
    }
    catch {
        Write-ColorMessage "✗ 网络连通性检测失败: $($_.Exception.Message)" $Colors.Error
        Write-DebugMessage "网络连通性测试异常: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# 函数：测试WinRM连接
function Test-WinRMConnection {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-ColorMessage "正在测试WinRM连接..." $Colors.Info
    
    try {
        $params = @{
            ComputerName = $ComputerName
            ErrorAction = 'Stop'
        }
        
        if ($Credential) {
            $params['Credential'] = $Credential
        }
        
        $result = Test-WSMan @params
        
        if ($result) {
            Write-ColorMessage "✓ WinRM连接测试成功" $Colors.Success
            return $true
        }
    }
    catch {
        Write-ColorMessage "✗ WinRM连接测试失败: $($_.Exception.Message)" $Colors.Warning
        return $false
    }
    
    return $false
}

# 函数：测试WMI连接（使用CIM会话优化）
function Test-WMIConnection {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-ColorMessage "正在测试WMI连接..." $Colors.Info
    Write-DebugMessage "开始WMI连接测试目标: $ComputerName" "WMI"
    
    try {
        $startTime = Get-Date
        
        # 创建CIM会话选项（使用DCOM协议）
        Write-DebugMessage "创建CIM会话选项 (DCOM协议)" "WMI"
        $sessionOption = New-CimSessionOption -Protocol Dcom
        
        # 创建CIM会话参数
        $sessionParams = @{
            ComputerName = $ComputerName
            SessionOption = $sessionOption
            ErrorAction = 'Stop'
        }
        
        if ($Credential) {
            $sessionParams['Credential'] = $Credential
            Write-DebugMessage "使用提供的凭据" "WMI"
        } else {
            Write-DebugMessage "使用当前用户凭据" "WMI"
        }
        
        # 创建临时CIM会话进行测试
        Write-DebugMessage "创建临时CIM会话..." "WMI"
        $testSession = New-CimSession @sessionParams
        $sessionTime = Get-Date
        $sessionDuration = ($sessionTime - $startTime).TotalMilliseconds
        Write-DebugMessage "CIM会话创建耗时: $($sessionDuration.ToString('F2'))ms" "WMI"
        
        Write-DebugMessage "执行测试查询 Win32_ComputerSystem..." "WMI"
        $result = Get-CimInstance -CimSession $testSession -ClassName Win32_ComputerSystem | Select-Object -First 1
        $queryTime = Get-Date
        Write-DebugMessage "测试查询耗时: $(($queryTime - $sessionTime).TotalMilliseconds.ToString('F2'))ms" "WMI"
        
        # 清理测试会话
        Remove-CimSession -CimSession $testSession
        $endTime = Get-Date
        Write-DebugMessage "WMI连接测试总耗时: $(($endTime - $startTime).TotalMilliseconds.ToString('F2'))ms" "WMI"
        
        if ($result) {
            Write-ColorMessage "✓ WMI连接测试成功" $Colors.Success
            Write-DebugMessage "WMI连接测试成功，获取到计算机信息: $($result.Name)" "WMI"
            return $true
        }
    }
    catch {
        $endTime = Get-Date
        Write-ColorMessage "✗ WMI连接测试失败: $($_.Exception.Message)" $Colors.Warning
        Write-DebugMessage "WMI连接测试失败耗时: $(($endTime - $startTime).TotalMilliseconds.ToString('F2'))ms" "WMI"
        Write-DebugMessage "WMI连接异常详情: $($_.Exception.Message)" "ERROR"
        # 确保清理会话
        if ($testSession) {
            Remove-CimSession -CimSession $testSession -ErrorAction SilentlyContinue
        }
        return $false
    }
    
    return $false
}

# 函数：获取本地Administrators组成员
function Get-LocalAdminMembers {
    try {
        $adminMembers = @()
        $group = [ADSI]"WinNT://./Administrators,group"
        
        foreach ($member in $group.Members()) {
            try {
                $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                $memberPath = $member.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $member, $null)
                $memberType = $member.GetType().InvokeMember("Class", 'GetProperty', $null, $member, $null)
                
                # 解析成员来源
                $principalSource = "Unknown"
                if ($memberPath -like "*WinNT://*/") {
                    # 处理三段式路径：WinNT://DOMAIN/COMPUTER/USER (本地用户)
                    if ($memberPath -match 'WinNT://([^/]+)/([^/]+)/([^/]+)') {
                        $domainPart = $matches[1]  # 域名
                        $computerPart = $matches[2]  # 计算机名
                        $userPart = $matches[3]  # 用户名
                        
                        # 三段式表示本地用户，检查计算机名是否匹配
                        if ($computerPart.ToUpper() -eq $env:COMPUTERNAME.ToUpper()) {
                            $principalSource = "Local"
                        } else {
                            $principalSource = "Domain ($domainPart)"
                        }
                    }
                    # 处理两段式路径：WinNT://DOMAIN/USER (域用户/组)
                    elseif ($memberPath -match 'WinNT://([^/]+)/(.+)') {
                        $domainPart = $matches[1]
                        $namePart = $matches[2]
                        
                        # 检查是否是计算机名（本地）
                        if ($domainPart.ToUpper() -eq $env:COMPUTERNAME.ToUpper()) {
                            $principalSource = "Local"
                        } else {
                            $principalSource = "Domain ($domainPart)"
                        }
                    }
                }
                
                $adminMembers += @{
                    Name = $memberName
                    Type = $memberType
                    Source = $principalSource
                    Path = $memberPath
                }
            }
            catch {
                # 忽略解析错误
            }
        }
        
        return $adminMembers
    }
    catch {
        Write-ColorMessage "获取本地Administrators组成员失败: $($_.Exception.Message)" $Colors.Warning
        return @()
    }
}

# 函数：获取远程Administrators组成员
function Get-RemoteAdminMembers {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential,
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )
    
    try {
        $adminMembers = @()
        
        # 直接使用高效的CIM会话方式查询管理员组成员
        Write-ColorMessage "使用CIM会话查询管理员组成员..." $Colors.Info
        Write-DebugMessage "开始CIM方式查询管理员组成员" "ADMIN"
        
        try {
            $startTime = Get-Date
            
            # 使用已建立的CIM会话获取计算机名
            Write-DebugMessage "获取计算机系统信息..." "ADMIN"
            $computerSystemInfo = Get-CimInstance -CimSession $cimSession -ClassName Win32_ComputerSystem
            $computerName = $computerSystemInfo.Name
            $sysTime = Get-Date
            Write-DebugMessage "获取到计算机名: $computerName，耗时: $(($sysTime - $startTime).TotalMilliseconds.ToString('F2'))ms" "ADMIN"
            
            # 使用CIM会话查询组用户关联关系
            Write-DebugMessage "查询Win32_GroupUser关联关系..." "ADMIN"
            $groupUsers = Get-CimInstance -CimSession $cimSession -ClassName Win32_GroupUser | 
                Where-Object { $_.GroupComponent -match "Administrators" }
            $queryTime = Get-Date
            Write-DebugMessage "组用户关联查询完成，找到 $($groupUsers.Count) 个关联，耗时: $(($queryTime - $sysTime).TotalMilliseconds.ToString('F2'))ms" "ADMIN"
            
            $wmiMembers = @()
            $processedCount = 0
            foreach ($groupUser in $groupUsers) {
                $processedCount++
                try {
                    Write-DebugMessage "处理第 $processedCount 个关联: $($groupUser.PartComponent)" "ADMIN"
                    
                    # CIM对象的格式是: Win32_UserAccount (Name = "Administrator", Domain = "IMZSPC1097")
                    if ($groupUser.PartComponent -match 'Win32_UserAccount.*Name = "([^"]+)".*Domain = "([^"]+)"') {
                        $memberName = $matches[1]
                        $memberDomain = $matches[2]
                        $memberType = "User"
                        
                        Write-DebugMessage "解析成功 - 用户成员: $memberDomain\$memberName" "ADMIN"
                        
                        $wmiMembers += @{
                            Domain = $memberDomain
                            Name = $memberName
                            CimClass = @{ CimClassName = "Win32_UserAccount" }
                        }
                    }
                    elseif ($groupUser.PartComponent -match 'Win32_Group.*Name = "([^"]+)".*Domain = "([^"]+)"') {
                        $memberName = $matches[1]
                        $memberDomain = $matches[2]
                        $memberType = "Group"
                        
                        Write-DebugMessage "解析成功 - 组成员: $memberDomain\$memberName" "ADMIN"
                        
                        $wmiMembers += @{
                            Domain = $memberDomain
                            Name = $memberName
                            CimClass = @{ CimClassName = "Win32_Group" }
                        }
                    }
                    else {
                        Write-DebugMessage "未匹配的组件格式: $($groupUser.PartComponent)" "ADMIN"
                    }
                }
                catch {
                    Write-DebugMessage "解析第 $processedCount 个组成员失败: $($_.Exception.Message)" "ERROR"
                }
            }
            
            $parseTime = Get-Date
            Write-DebugMessage "成员解析完成，成功解析 $($wmiMembers.Count) 个成员，耗时: $(($parseTime - $queryTime).TotalMilliseconds.ToString('F2'))ms" "ADMIN"
            
            # 转换为标准格式
            foreach ($member in $wmiMembers) {
                try {
                    $memberDomain = $member.Domain
                    $memberName = $member.Name
                    $memberType = if ($member.CimClass.CimClassName -eq "Win32_UserAccount") { "User" } else { "Group" }
                    
                    # 判断是本地还是域成员
                    $principalSource = if ($memberDomain -eq $computerName) { "Local" } else { "Domain ($memberDomain)" }
                    
                    $adminMembers += @{
                        Name = $memberName
                        Type = $memberType
                        Source = $principalSource
                        Path = "CIM: $memberDomain\$memberName"
                    }
                    
                    Write-DebugMessage "添加管理员成员: $memberName [$memberType] ($principalSource)" "ADMIN"
                }
                catch {
                    Write-DebugMessage "转换成员格式失败: $($_.Exception.Message)" "ERROR"
                }
            }
            
            $endTime = Get-Date
            Write-DebugMessage "管理员组查询总耗时: $(($endTime - $startTime).TotalMilliseconds.ToString('F2'))ms，最终获取 $($adminMembers.Count) 个成员" "ADMIN"
        }
        catch {
            Write-DebugMessage "CIM管理员组查询失败: $($_.Exception.Message)" "ERROR"
            Write-ColorMessage "获取管理员组成员失败: $($_.Exception.Message)" $Colors.Warning
        }
        
        return $adminMembers
    }
    catch {
        Write-ColorMessage "获取远程Administrators组成员失败: $($_.Exception.Message)" $Colors.Warning
        return @()
    }
}

# 函数：获取本地系统信息
function Get-LocalSystemInfo {
    $info = @{}
    
    try {
        Write-ColorMessage "正在获取计算机信息..." $Colors.Info
    $computerName = $env:COMPUTERNAME
    $domain = $env:USERDOMAIN
    $fqdn = "$computerName.$domain"
    
    try {
        $fqdnFull = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
        if ($fqdnFull -and $fqdnFull -ne $computerName) {
            $fqdn = $fqdnFull
        }
    }
    catch {
            # 使用基本的计算机名
    }
    
        $info.ComputerName = $fqdn
    
        Write-ColorMessage "正在获取用户信息..." $Colors.Info
    $currentUser = $env:USERNAME
    $userDomain = $env:USERDOMAIN
        $info.CurrentUser = "$userDomain\$currentUser"
        
        Write-ColorMessage "正在获取网络信息..." $Colors.Info
        $info.NetworkAdapters = @()
        
        $networkAdapters = Get-NetAdapter | Where-Object { 
            $_.Status -eq "Up" -and 
            $_.Name -notlike "*Loopback*" -and
            $_.Name -notlike "*Teredo*" -and
            $_.Name -notlike "*isatap*" -and
            $_.Name -notlike "*Bluetooth*"
        }
        
        foreach ($adapter in $networkAdapters) {
            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                       Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -ne "0.0.0.0" }
            
            if ($ipConfig) {
                # 获取DNS服务器信息
                $dnsServers = @()
                try {
                    $dnsConfig = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
                    if ($dnsConfig -and $dnsConfig.ServerAddresses) {
                        $dnsServers = $dnsConfig.ServerAddresses | Where-Object { $_ -ne "127.0.0.1" -and $_ -ne "::1" }
                    }
                }
                catch {
                    # 忽略DNS查询错误
                }
                
                $info.NetworkAdapters += @{
                    Name = $adapter.Name
                    IPAddress = $ipConfig.IPAddress
                    MACAddress = $adapter.MacAddress
                    DNSServers = $dnsServers
                    Type = if ($adapter.Virtual) { "虚拟网卡" } else { "物理网卡" }
                }
            }
        }
        
        Write-ColorMessage "正在获取系统详细信息..." $Colors.Info
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
        
        $info.OSName = $osInfo.Caption
        $info.OSVersion = $osInfo.Version
        $info.OSArchitecture = $osInfo.OSArchitecture
        $info.Manufacturer = $computerInfo.Manufacturer
        $info.Model = $computerInfo.Model
        $info.TotalMemoryGB = [math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)
        
        # 获取本地Administrators组成员
        Write-ColorMessage "正在获取Administrators组成员..." $Colors.Info
        $info.AdminMembers = Get-LocalAdminMembers
        
        return $info
    }
    catch {
        throw "获取本地系统信息失败: $($_.Exception.Message)"
    }
}

# 函数：获取远程系统信息（WinRM方式）
function Get-RemoteSystemInfoWinRM {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-ColorMessage "正在通过WinRM获取远程系统信息..." $Colors.Info
    
    $scriptBlock = {
        $result = @{}
        
        $result.ComputerName = $env:COMPUTERNAME
        $result.CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
        
        $result.NetworkAdapters = @()
    $networkAdapters = Get-NetAdapter | Where-Object { 
        $_.Status -eq "Up" -and 
        $_.Name -notlike "*Loopback*" -and
        $_.Name -notlike "*Teredo*" -and
            $_.Name -notlike "*isatap*" -and
            $_.Name -notlike "*Bluetooth*"
    }
    
    foreach ($adapter in $networkAdapters) {
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                   Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -ne "0.0.0.0" }
        
        if ($ipConfig) {
                # 获取DNS服务器信息
                $dnsServers = @()
                try {
                    $dnsConfig = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
                    if ($dnsConfig -and $dnsConfig.ServerAddresses) {
                        $dnsServers = $dnsConfig.ServerAddresses | Where-Object { $_ -ne "127.0.0.1" -and $_ -ne "::1" }
                    }
                }
                catch {
                    # 忽略DNS查询错误
                }
                
                $result.NetworkAdapters += @{
                    Name = $adapter.Name
                    IPAddress = $ipConfig.IPAddress
                    MACAddress = $adapter.MacAddress
                    DNSServers = $dnsServers
                    Type = if ($adapter.Virtual) { "虚拟网卡" } else { "物理网卡" }
                }
            }
        }
        
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
        
        $result.OSName = $osInfo.Caption
        $result.OSVersion = $osInfo.Version
        $result.OSArchitecture = $osInfo.OSArchitecture
        $result.Manufacturer = $computerInfo.Manufacturer
        $result.Model = $computerInfo.Model
        $result.TotalMemoryGB = [math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)
        
        # 获取Administrators组成员
        try {
            $adminMembers = @()
            $group = [ADSI]"WinNT://./Administrators,group"
            foreach ($member in $group.Members()) {
                try {
                    $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                    $memberPath = $member.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $member, $null)
                    $memberType = $member.GetType().InvokeMember("Class", 'GetProperty', $null, $member, $null)
                    
                    # 解析成员来源
                    $principalSource = "Unknown"
                    if ($memberPath -like "*WinNT://*/") {
                        if ($memberPath -like "*WinNT://$env:COMPUTERNAME/*") {
                            $principalSource = "Local"
                        } else {
                            $match = [regex]::Match($memberPath, 'WinNT://([^/]+)/')
                            if ($match.Success) {
                                $sourceName = $match.Groups[1].Value
                                if ($sourceName -ne $env:COMPUTERNAME) {
                                    $principalSource = "Domain ($sourceName)"
                                } else {
                                    $principalSource = "Local"
                                }
                            }
                        }
                    }
                    
                    $adminMembers += @{
                        Name = $memberName
                        Type = $memberType
                        Source = $principalSource
                        Path = $memberPath
                    }
                }
                catch {
                    # 忽略解析错误
                }
            }
            $result.AdminMembers = $adminMembers
        }
        catch {
            $result.AdminMembers = @()
        }
        
        return $result
    }
    
    $params = @{
        ComputerName = $ComputerName
        ScriptBlock = $scriptBlock
        ErrorAction = 'Stop'
    }
    
    if ($Credential) {
        $params['Credential'] = $Credential
    }
    
    return Invoke-Command @params
}

# 函数：获取远程系统信息（WMI方式）
function Get-RemoteSystemInfoWMI {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-ColorMessage "正在通过WMI获取远程系统信息..." $Colors.Info
    
    $info = @{}
    
    # 使用CIM会话提高性能
    Write-ColorMessage "正在建立CIM连接..." $Colors.Info
    try {
        # 创建CIM会话选项（使用DCOM协议）
        $sessionOption = New-CimSessionOption -Protocol Dcom
        
        # 创建CIM会话参数
        $sessionParams = @{
            ComputerName = $ComputerName
            SessionOption = $sessionOption
            ErrorAction = 'Stop'
        }
        
        if ($Credential) {
            $sessionParams['Credential'] = $Credential
        }
        
        # 创建CIM会话
        $cimSession = New-CimSession @sessionParams
        Write-ColorMessage "CIM连接建立成功" $Colors.Success
        
        # 获取计算机基本信息（使用CIM会话）
        $computerInfo = Get-CimInstance -CimSession $cimSession -ClassName Win32_ComputerSystem
        $osInfo = Get-CimInstance -CimSession $cimSession -ClassName Win32_OperatingSystem
    
    # 获取完整的计算机名（FQDN）
    try {
        # 优先从计算机系统信息获取域名
        $computerName = $computerInfo.Name
        $domainName = $computerInfo.Domain
        
        if ($domainName -and $domainName -ne "WORKGROUP") {
            # 如果计算机加入了域，使用 计算机名.域名 格式
            $info.ComputerName = "$computerName.$domainName"
        } else {
            # 如果不在域中，检查是否为IP地址
            # 检查输入的ComputerName是否为IP地址
            $isIPAddress = $false
            try {
                [System.Net.IPAddress]::Parse($ComputerName) | Out-Null
                $isIPAddress = $true
            }
            catch {
                $isIPAddress = $false
            }
            
            if ($isIPAddress) {
                # 对于IP地址，直接使用计算机名，不进行DNS反向解析以避免性能问题
                Write-ColorMessage "检测到IP地址，跳过DNS反向解析以提高性能" $Colors.Info
                $info.ComputerName = $computerName
            } else {
                # 对于域名，使用基本计算机名
                $info.ComputerName = $computerName
            }
        }
    }
    catch {
        # 如果所有方法都失败，使用输入的计算机名
        $info.ComputerName = $ComputerName
    }
    
    # 获取当前登录用户
    try {
        Write-ColorMessage "正在获取当前登录用户..." $Colors.Info
        $currentUsers = @()
        
        # 使用CIM会话的超高效用户查询方法
        Write-ColorMessage "正在查询登录用户（CIM优化方法）..." $Colors.Info
        Write-DebugMessage "开始用户会话查询" "USER"
        try {
            $startTime = Get-Date
            $users = @()
            $logonIdMap = @{}
            $validLogonTypes = @(2, 10)  # 交互式和远程交互式
            
            # 使用CIM会话获取登录会话，性能更优
            Write-DebugMessage "查询Win32_LogonSession..." "USER"
            $logonSessions = Get-CimInstance -CimSession $cimSession -ClassName Win32_LogonSession | 
                Where-Object { $validLogonTypes -contains $_.LogonType }
            $sessionTime = Get-Date
            Write-DebugMessage "登录会话查询耗时: $(($sessionTime - $startTime).TotalMilliseconds.ToString('F2'))ms" "USER"
            
            Write-ColorMessage "找到 $($logonSessions.Count) 个相关登录会话" $Colors.Info
            Write-DebugMessage "找到 $($logonSessions.Count) 个有效登录会话 (类型: $($validLogonTypes -join ','))" "USER"
            
            # 创建LogonId哈希表以提高查找性能
            foreach ($session in $logonSessions) {
                $logonIdMap[$session.LogonId] = $true
            }
            
            # 使用CIM会话预加载用户信息（User-LogonSession关联）
            Write-DebugMessage "查询Win32_LoggedOnUser关联信息..." "USER"
            $loggedOnUsers = Get-CimInstance -CimSession $cimSession -ClassName Win32_LoggedOnUser
            $userTime = Get-Date
            Write-DebugMessage "用户关联查询耗时: $(($userTime - $sessionTime).TotalMilliseconds.ToString('F2'))ms，找到 $($loggedOnUsers.Count) 个关联" "USER"
            
            $processedUsers = 0
            $validUsers = 0
            $skippedUsers = 0
            
            foreach ($assoc in $loggedOnUsers) {
                $processedUsers++
                
                # 使用正则表达式直接提取LogonId，支持CIM对象格式
                if ($assoc.Dependent -match 'LogonId = "(\d+)"' -or $assoc.Dependent -match 'LogonId="(\d+)"') {
                    $logonId = $matches[1]
                    
                    # 使用哈希表快速检查LogonId是否有效
                    if ($logonIdMap.ContainsKey($logonId)) {
                        try {
                            Write-DebugMessage "处理第 $processedUsers 个用户关联，LogonId: $logonId" "USER"
                            Write-DebugMessage "关联信息: $($assoc.Antecedent)" "USER"
                            
                            # 解析用户信息，支持多种格式 - CIM对象格式
                            if ($assoc.Antecedent -match 'Win32_Account.*Name = "([^"]+)".*Domain = "([^"]+)"') {
                                $userName = $matches[1]
                                $userDomain = $matches[2]
                                $fullName = "$userDomain\$userName"
                                
                                Write-DebugMessage "解析成功 - 用户: $fullName" "USER"
                                
                                # 使用更严格的真实用户检查
                                if ((Test-IsRealUser -UserName $userName -UserDomain $userDomain) -and $users -notcontains $fullName) {
                                    $users += $fullName
                                    $validUsers++
                                    Write-DebugMessage "✓ 添加真实用户: $fullName (LogonId: $logonId)" "USER"
                                } else {
                                    $skippedUsers++
                                    if ($users -contains $fullName) {
                                        Write-DebugMessage "✗ 跳过重复用户: $fullName" "USER"
                                    } else {
                                        Write-DebugMessage "✗ 跳过系统虚拟账户: $fullName" "USER"
                                    }
                                }
                            }
                            elseif ($assoc.Antecedent -match 'Win32_UserAccount[^"]*Domain="([^"]+)"[^"]*Name="([^"]+)"') {
                                $userDomain = $matches[1]
                                $userName = $matches[2]
                                $fullName = "$userDomain\$userName"
                                
                                Write-DebugMessage "解析成功 - 用户: $fullName" "USER"
                                
                                # 使用更严格的真实用户检查
                                if ((Test-IsRealUser -UserName $userName -UserDomain $userDomain) -and $users -notcontains $fullName) {
                                    $users += $fullName
                                    $validUsers++
                                    Write-DebugMessage "✓ 添加真实用户: $fullName (LogonId: $logonId)" "USER"
                                } else {
                                    $skippedUsers++
                                    if ($users -contains $fullName) {
                                        Write-DebugMessage "✗ 跳过重复用户: $fullName" "USER"
                                    } else {
                                        Write-DebugMessage "✗ 跳过系统虚拟账户: $fullName" "USER"
                                    }
                                }
                            }
                            elseif ($assoc.Antecedent -match 'Win32_Group[^"]*Domain="([^"]+)"[^"]*Name="([^"]+)"') {
                                $userDomain = $matches[1]
                                $userName = $matches[2]
                                $fullName = "$userDomain\$userName"
                                $skippedUsers++
                                
                                Write-DebugMessage "✗ 跳过组对象: $fullName" "USER"
                            }
                            else {
                                $skippedUsers++
                                Write-DebugMessage "✗ 未匹配的用户格式: $($assoc.Antecedent)" "USER"
                            }
                        } catch {
                            $skippedUsers++
                            Write-DebugMessage "✗ 解析第 $processedUsers 个用户失败: $($_.Exception.Message)" "ERROR"
                        }
                    } else {
                        $skippedUsers++
                        Write-DebugMessage "✗ LogonId $logonId 不在有效会话中，跳过" "USER"
                    }
                } else {
                    $skippedUsers++
                    Write-DebugMessage "✗ 无法提取LogonId，跳过关联: $($assoc.Dependent)" "USER"
                }
            }
            
            $endTime = Get-Date
            Write-DebugMessage "用户查询统计: 总关联数=$processedUsers, 有效用户=$validUsers, 跳过数=$skippedUsers, 最终用户数=$($users.Count)" "USER"
            Write-DebugMessage "用户查询总耗时: $(($endTime - $startTime).TotalMilliseconds.ToString('F2'))ms" "USER"
            
            if ($users.Count -gt 0) {
                $currentUsers = $users
            }
        }
        catch {
            Write-ColorMessage "CIM用户查询方法失败，使用备用方法: $($_.Exception.Message)" $Colors.Warning
            $currentUsers = @()
        }
        
        # 方法2：如果上面没找到用户，尝试直接查询Win32_ComputerSystem的UserName属性
        if ($currentUsers.Count -eq 0) {
            Write-ColorMessage "尝试通过Win32_ComputerSystem获取用户信息..." $Colors.Info
            try {
                if ($computerInfo.UserName -and $computerInfo.UserName -ne "") {
                    $currentUsers += $computerInfo.UserName
                }
            }
            catch {
                # 忽略错误
            }
        }
        
        # 方法3：如果还是没找到，使用CIM会话查询进程所有者
        if ($currentUsers.Count -eq 0) {
            Write-ColorMessage "尝试通过进程所有者获取用户信息（CIM优化）..." $Colors.Info
            try {
                # 使用CIM会话查询关键进程
                $processes = Get-CimInstance -CimSession $cimSession -ClassName Win32_Process | 
                    Where-Object { $_.Name -eq "explorer.exe" -or $_.Name -eq "dwm.exe" } |
                    Select-Object -First 5  # 限制查询数量提高性能
                
                foreach ($process in $processes) {
                    try {
                        # 使用CIM方法调用获取进程所有者
                        $owner = Invoke-CimMethod -CimSession $cimSession -InputObject $process -MethodName GetOwner
                        if ($owner.Domain -and $owner.User) {
                            $fullName = "$($owner.Domain)\$($owner.User)"
                            if ($owner.User -notmatch '^(DWM-|UMFD-|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|IUSR_|IWAM_|DefaultAccount|Guest|Administrator\$)' -and 
                                $currentUsers -notcontains $fullName) {
                                $currentUsers += $fullName
                            }
                        }
                    }
                    catch {
                        # 忽略错误
                    }
                }
            }
            catch {
                # 忽略错误
            }
        }
        
        if ($currentUsers.Count -gt 0) {
            $info.CurrentUser = ($currentUsers | Sort-Object -Unique) -join ", "
        } else {
            $info.CurrentUser = "无活动用户会话"
        }
        }
        catch {
            $info.CurrentUser = "获取用户信息失败: $($_.Exception.Message)"
        }
    
    # 获取网络适配器信息（使用CIM会话优化性能）
    $info.NetworkAdapters = @()
    
    Write-ColorMessage "正在获取网络适配器信息..." $Colors.Info
    Write-DebugMessage "开始网络适配器查询" "NETWORK"
    
    try {
        $startTime = Get-Date
        
        # 使用CIM会话一次性获取所有网络配置信息
        Write-DebugMessage "查询Win32_NetworkAdapterConfiguration..." "NETWORK"
        $allNetworkConfigs = Get-CimInstance -CimSession $cimSession -ClassName Win32_NetworkAdapterConfiguration
        $queryTime = Get-Date
        Write-DebugMessage "网络配置查询完成，找到 $($allNetworkConfigs.Count) 个配置，耗时: $(($queryTime - $startTime).TotalMilliseconds.ToString('F2'))ms" "NETWORK"
        
        # 过滤有效的网络配置
        $networkConfigs = $allNetworkConfigs | Where-Object { $_.IPEnabled -eq $true -and $_.IPAddress -and $_.MACAddress }
        Write-DebugMessage "过滤后有效网络配置: $($networkConfigs.Count) 个" "NETWORK"
        
        $adapterCount = 0
        foreach ($config in $networkConfigs) {
            $adapterCount++
            if ($config.IPAddress) {
                Write-DebugMessage "处理第 $adapterCount 个适配器: $($config.Description)" "NETWORK"
                Write-DebugMessage "IP地址: $($config.IPAddress[0]), MAC: $($config.MACAddress)" "NETWORK"
                
                # 获取DNS服务器信息
                $dnsServers = @()
                if ($config.DNSServerSearchOrder) {
                    $allDNS = $config.DNSServerSearchOrder
                    $dnsServers = $allDNS | Where-Object { $_ -ne "127.0.0.1" -and $_ -ne "::1" }
                    Write-DebugMessage "DNS服务器: $($dnsServers -join ', ') (过滤前: $($allDNS -join ', '))" "NETWORK"
                } else {
                    Write-DebugMessage "未配置DNS服务器" "NETWORK"
                }
                
                # 判断网卡类型
                $adapterType = if ($config.Description -like "*Virtual*" -or $config.Description -like "*VMware*" -or $config.Description -like "*Hyper-V*") { "虚拟网卡" } else { "物理网卡" }
                Write-DebugMessage "适配器类型: $adapterType" "NETWORK"
                
                $info.NetworkAdapters += @{
                    Name = if ($config.Description) { $config.Description } else { "Unknown Adapter" }
                    IPAddress = $config.IPAddress[0]
                    MACAddress = $config.MACAddress
                    DNSServers = $dnsServers
                    Type = $adapterType
                }
                
                Write-DebugMessage "✓ 添加网络适配器: $($config.Description)" "NETWORK"
            }
        }
        
        $endTime = Get-Date
        Write-DebugMessage "网络适配器查询总耗时: $(($endTime - $startTime).TotalMilliseconds.ToString('F2'))ms，获取 $($info.NetworkAdapters.Count) 个有效适配器" "NETWORK"
    }
    catch {
        Write-DebugMessage "网络适配器查询失败: $($_.Exception.Message)" "ERROR"
        Write-ColorMessage "获取网络适配器信息失败: $($_.Exception.Message)" $Colors.Warning
        $info.NetworkAdapters = @()
    }
    
    # 获取系统详细信息
    $info.OSName = $osInfo.Caption
    $info.OSVersion = $osInfo.Version
    $info.OSArchitecture = $osInfo.OSArchitecture
    $info.Manufacturer = $computerInfo.Manufacturer
    $info.Model = $computerInfo.Model
    $info.TotalMemoryGB = [math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)
    
    # 获取远程Administrators组成员
    Write-ColorMessage "正在获取Administrators组成员..." $Colors.Info
    $info.AdminMembers = Get-RemoteAdminMembers -ComputerName $ComputerName -Credential $Credential -CimSession $cimSession
    
    # 清理CIM会话
    if ($cimSession) {
        Remove-CimSession -CimSession $cimSession
        Write-ColorMessage "CIM会话已清理" $Colors.Info
    }
    
    return $info
    }
    catch {
        # 确保在异常情况下也清理CIM会话
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
        }
        throw
    }
}

# 函数：显示系统信息
function Show-SystemInfo {
    param($SystemInfo, $IsRemote = $false, $ConnectionMethod = "")
    
    $outputContent = @()
    $outputContent += "系统信息查询结果 - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    if ($IsRemote) {
        $outputContent += "远程目标: $($SystemInfo.ComputerName)"
        $outputContent += "连接方式: $ConnectionMethod"
    }
    $outputContent += "=" * 50
    
    Write-ColorMessage "计算机名 (FQDN): $($SystemInfo.ComputerName)" $Colors.Success
    $outputContent += "计算机名 (FQDN): $($SystemInfo.ComputerName)"
    
    Write-ColorMessage "当前登录用户: $($SystemInfo.CurrentUser)" $Colors.Success
    $outputContent += "当前登录用户: $($SystemInfo.CurrentUser)"
    $outputContent += ""
    
    $outputContent += "网络适配器信息:"
    $outputContent += "-" * 30
    
    if ($SystemInfo.NetworkAdapters -and $SystemInfo.NetworkAdapters.Count -gt 0) {
        $adapterCount = 0
        foreach ($adapter in $SystemInfo.NetworkAdapters) {
            $adapterCount++
            
            Write-Host ""
            Write-ColorMessage "网卡 $adapterCount - $($adapter.Name) ($($adapter.Type))" $Colors.Warning
            Write-ColorMessage "  IP地址: $($adapter.IPAddress)" $Colors.Success
            Write-ColorMessage "  MAC地址: $($adapter.MACAddress)" $Colors.Success
            
            # 显示DNS服务器
            if ($adapter.DNSServers -and $adapter.DNSServers.Count -gt 0) {
                $dnsString = $adapter.DNSServers -join ", "
                Write-ColorMessage "  DNS服务器: $dnsString" $Colors.Success
                $outputContent += "网卡 $adapterCount - $($adapter.Name) ($($adapter.Type))"
                $outputContent += "  IP地址: $($adapter.IPAddress)"
                $outputContent += "  MAC地址: $($adapter.MACAddress)"
                $outputContent += "  DNS服务器: $dnsString"
            } else {
                Write-ColorMessage "  DNS服务器: 未配置或自动获取" $Colors.Info
                $outputContent += "网卡 $adapterCount - $($adapter.Name) ($($adapter.Type))"
                $outputContent += "  IP地址: $($adapter.IPAddress)"
                $outputContent += "  MAC地址: $($adapter.MACAddress)"
                $outputContent += "  DNS服务器: 未配置或自动获取"
            }
            $outputContent += ""
        }
    } else {
        Write-ColorMessage "未找到活动的网络连接" $Colors.Error
        $outputContent += "未找到活动的网络连接"
    }
    
    $outputContent += "系统详细信息:"
    $outputContent += "-" * 30
    
    Write-Host ""
    Write-ColorMessage "操作系统: $($SystemInfo.OSName)" $Colors.Success
    Write-ColorMessage "系统版本: $($SystemInfo.OSVersion)" $Colors.Success
    Write-ColorMessage "系统架构: $($SystemInfo.OSArchitecture)" $Colors.Success
    Write-ColorMessage "制造商: $($SystemInfo.Manufacturer)" $Colors.Success
    Write-ColorMessage "型号: $($SystemInfo.Model)" $Colors.Success
    Write-ColorMessage "总内存: $($SystemInfo.TotalMemoryGB) GB" $Colors.Success
    
    $outputContent += "操作系统: $($SystemInfo.OSName)"
    $outputContent += "系统版本: $($SystemInfo.OSVersion)"
    $outputContent += "系统架构: $($SystemInfo.OSArchitecture)"
    $outputContent += "制造商: $($SystemInfo.Manufacturer)"
    $outputContent += "型号: $($SystemInfo.Model)"
    $outputContent += "总内存: $($SystemInfo.TotalMemoryGB) GB"
    
        # 显示Administrators组成员
    $outputContent += ""
    $outputContent += "Administrators组成员:"
    $outputContent += "-" * 30
    
    if ($SystemInfo.AdminMembers -and $SystemInfo.AdminMembers.Count -gt 0) {
        # 分类显示成员
        $localMembers = @()
        $domainMembers = @()
        
        foreach ($member in $SystemInfo.AdminMembers) {
            # 使用Source字段判断是本地还是域成员（更准确）
            $isLocal = $false
            
            if ($member.Source -eq "Local") {
                $isLocal = $true
            } elseif ($member.Source -like "Domain (*") {
                $isLocal = $false
            } else {
                # 备用判断：如果Source字段不明确，则根据路径判断
                if ($member.Path -match 'WinNT://([^/]+)/([^/]+)/([^/]+)') {
                    # 三段式路径：WinNT://DOMAIN/COMPUTER/USER (本地成员)
                    $isLocal = $true
                } elseif ($member.Path -match 'WinNT://([^/]+)/(.+)') {
                    # 两段式路径：WinNT://DOMAIN/USER (可能是域成员或本地成员)
                    $domainPart = $matches[1]
                    $namePart = $matches[2]
                    
                    # 检查是否是计算机名
                    if ($IsRemoteQuery) {
                        $targetComputer = $ComputerName.Split('.')[0].ToUpper()
                        $isLocal = ($domainPart.ToUpper() -eq $targetComputer)
                    } else {
                        $isLocal = ($domainPart.ToUpper() -eq $env:COMPUTERNAME.ToUpper())
                    }
                } elseif ($member.Path -like "CIM: *") {
                    # CIM格式：CIM: DOMAIN\USER
                    if ($member.Path -match 'CIM: ([^\\]+)\\(.+)') {
                        $domainPart = $matches[1]
                        $namePart = $matches[2]
                        
                        # 检查是否是计算机名
                        if ($IsRemoteQuery) {
                            $targetComputer = $ComputerName.Split('.')[0].ToUpper()
                            $isLocal = ($domainPart.ToUpper() -eq $targetComputer)
                        } else {
                            $isLocal = ($domainPart.ToUpper() -eq $env:COMPUTERNAME.ToUpper())
                        }
                    }
                }
            }
            
            if ($isLocal) {
                $localMembers += $member
            } else {
                $domainMembers += $member
            }
        }
        
        # 显示本地成员
        if ($localMembers.Count -gt 0) {
            Write-Host ""
            Write-ColorMessage "🏠 本地成员 ($($localMembers.Count) 个):" $Colors.Success
            $outputContent += ""
            $outputContent += "🏠 本地成员 ($($localMembers.Count) 个):"
            
            $localCount = 0
            foreach ($member in $localMembers) {
                $localCount++
                Write-ColorMessage "  $localCount. $($member.Name) [$($member.Type)]" $Colors.Info
                $outputContent += "  $localCount. $($member.Name) [$($member.Type)]"
            }
        }
        
        # 显示域成员
        if ($domainMembers.Count -gt 0) {
            Write-Host ""
            Write-ColorMessage "🌐 域成员 ($($domainMembers.Count) 个):" $Colors.Warning
            $outputContent += ""
            $outputContent += "🌐 域成员 ($($domainMembers.Count) 个):"
            
            $domainCount = 0
            foreach ($member in $domainMembers) {
                $domainCount++
                Write-ColorMessage "  $domainCount. $($member.Name) [$($member.Type)]" $Colors.Info
                $outputContent += "  $domainCount. $($member.Name) [$($member.Type)]"
            }
        }
    
    Write-Host ""
        Write-ColorMessage "📊 总计: $($SystemInfo.AdminMembers.Count) 个Administrators组成员" $Colors.Success
        $outputContent += ""
        $outputContent += "📊 总计: $($SystemInfo.AdminMembers.Count) 个Administrators组成员"
    } else {
        Write-ColorMessage "未找到Administrators组成员或获取失败" $Colors.Error
        $outputContent += "未找到Administrators组成员或获取失败"
    }
    
    return $outputContent
}

# ===================================================================
# 主执行逻辑
# ===================================================================

# 显示标题
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "    系统信息查询工具" -ForegroundColor Yellow
Write-Host "  System Information Tool" -ForegroundColor Yellow
if ($IsRemoteQuery) {
    Write-Host "  远程目标: $TargetComputer" -ForegroundColor Yellow
}
Write-Host "=================================" -ForegroundColor Cyan
    Write-Host ""

# 初始化变量
$SystemInfo = $null
$ConnectionMethod = $null
$clipboardSuccess = $false
$clipboardError = ""

try {
    if ($IsRemoteQuery) {
        Write-ColorMessage "开始远程系统信息查询..." $Colors.Header
        
        # 测试网络连通性
        if (-not (Test-NetworkConnectivity -TargetComputer $ComputerName)) {
            throw "无法连接到远程计算机: $ComputerName"
        }
        
        # 测试连接方式
        $winrmAvailable = $false
        $wmiAvailable = $false
        
        if ($UseWinRM) {
            Write-ColorMessage "用户指定使用WinRM，正在测试WinRM连接..." $Colors.Info
            $winrmAvailable = Test-WinRMConnection -ComputerName $ComputerName -Credential $Credential
            
            if (-not $winrmAvailable) {
                Write-ColorMessage "WinRM连接失败，尝试WMI连接..." $Colors.Warning
                $wmiAvailable = Test-WMIConnection -ComputerName $ComputerName -Credential $Credential
            }
        } else {
            Write-ColorMessage "默认使用WMI连接（更快速），如需使用WinRM请添加 -UseWinRM 参数" $Colors.Info
            $wmiAvailable = Test-WMIConnection -ComputerName $ComputerName -Credential $Credential
        }
        
        # 选择连接方式并获取信息
        if ($winrmAvailable) {
            $ConnectionMethod = "WinRM"
            Write-ColorMessage "✓ 使用WinRM连接方式" $Colors.Success
            $SystemInfo = Get-RemoteSystemInfoWinRM -ComputerName $ComputerName -Credential $Credential
        } elseif ($wmiAvailable) {
            $ConnectionMethod = "WMI"
            Write-ColorMessage "✓ 使用WMI连接方式" $Colors.Success
            $SystemInfo = Get-RemoteSystemInfoWMI -ComputerName $ComputerName -Credential $Credential
        } else {
            if ($UseWinRM) {
                throw "无法通过WinRM或WMI连接到远程计算机: $ComputerName"
            } else {
                throw "无法通过WMI连接到远程计算机: $ComputerName。如需尝试WinRM连接，请使用 -UseWinRM 参数"
            }
        }
    } else {
        Write-ColorMessage "开始本地系统信息查询..." $Colors.Header
        $SystemInfo = Get-LocalSystemInfo
    }
    
    # 显示系统信息
Write-Host ""
    $outputContent = Show-SystemInfo -SystemInfo $SystemInfo -IsRemote $IsRemoteQuery -ConnectionMethod $ConnectionMethod

    # 复制到剪切板
try {
    $outputContent += ""
    $outputContent += "========================================"
    $outputContent += "以上信息已自动复制到剪切板"
        if ($IsRemoteQuery) {
            $outputContent += "远程计算机: $ComputerName"
            $outputContent += "连接方式: $ConnectionMethod"
        }
    $outputContent += "请直接粘贴发送给IT工程师"
    $outputContent += "========================================"
    
    $clipboardContent = $outputContent -join "`r`n"
    $clipboardContent | Set-Clipboard
    
        $clipboardSuccess = $true
}
catch {
        $clipboardSuccess = $false
        $clipboardError = $_.Exception.Message
}

    # 保存到文件
if ($SaveToFile) {
    try {
        $outputContent | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-ColorMessage "信息已保存到文件: $OutputPath" $Colors.Success
    }
    catch {
            Write-ColorMessage "保存文件时发生错误: $($_.Exception.Message)" $Colors.Error
        }
    }
}
catch {
    $errorMessage = "获取系统信息时发生错误: $($_.Exception.Message)"
    Write-ColorMessage $errorMessage $Colors.Error
    
    Write-Host ""
    Write-Host "=================================" -ForegroundColor Cyan
    
    Write-ColorMessage "操作失败，可能的原因：" $Colors.Warning
    if ($IsRemoteQuery) {
        Write-ColorMessage "1. 远程计算机不可达或网络连接问题" $Colors.Info
        Write-ColorMessage "2. WinRM服务未启用或配置不正确" $Colors.Info
        Write-ColorMessage "3. WMI服务被禁用或防火墙阻止" $Colors.Info
        Write-ColorMessage "4. 用户权限不足或凭据无效" $Colors.Info
        Write-ColorMessage "5. 目标计算机的安全策略限制" $Colors.Info
    } else {
        Write-ColorMessage "1. 系统服务异常或权限不足" $Colors.Info
        Write-ColorMessage "2. PowerShell版本不兼容" $Colors.Info
        Write-ColorMessage "3. 系统资源不足或服务被禁用" $Colors.Info
    }
    
    exit 1
}
finally {
    $ScriptEndTime = Get-Date
    $ExecutionTime = $ScriptEndTime - $ScriptStartTime
    
    # 显示分隔线
    Write-Host ""
    Write-Host "=================================" -ForegroundColor Cyan
    
    # 显示醒目的剪切板提示信息
    if ($clipboardSuccess) {
        Write-Host ""
        Write-Host "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉" -ForegroundColor Green
        Write-Host "🎯 " -ForegroundColor Green -NoNewline
        Write-Host "以上信息已自动复制到剪切板！" -ForegroundColor Yellow -BackgroundColor DarkGreen
        Write-Host "📋 " -ForegroundColor Cyan -NoNewline
        Write-Host "请直接在IM软件（如钉钉、企业微信、飞书等）中粘贴发送给IT工程师" -ForegroundColor White -BackgroundColor DarkBlue
        if ($IsRemoteQuery) {
            Write-Host "🖥️  " -ForegroundColor Magenta -NoNewline
            Write-Host "远程计算机: $ComputerName | 连接方式: $ConnectionMethod" -ForegroundColor Yellow
        }
        Write-Host "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌" -ForegroundColor Red
        Write-Host "⚠️  " -ForegroundColor Red -NoNewline
        Write-Host "复制到剪切板失败！" -ForegroundColor White -BackgroundColor Red
        Write-Host "📝 " -ForegroundColor Yellow -NoNewline
        Write-Host "请手动复制上述信息" -ForegroundColor White -BackgroundColor DarkYellow
        Write-Host "🔧 " -ForegroundColor Cyan -NoNewline
        Write-Host "错误原因: $clipboardError" -ForegroundColor Red
        Write-Host "❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌❌" -ForegroundColor Red
    }
    
    Write-Host "=================================" -ForegroundColor Cyan

    Write-Host ""
    Write-ColorMessage "脚本执行完成！" $Colors.Header
    Write-ColorMessage "执行时间: $($ExecutionTime.TotalSeconds.ToString('F2')) 秒" $Colors.Info
Write-Host ""
    
    Write-ColorMessage "使用提示：" $Colors.Warning
    if ($IsRemoteQuery) {
        Write-ColorMessage "1. 如需查询其他计算机，请重新运行脚本" $Colors.Info
        Write-ColorMessage "2. 连接方式: $ConnectionMethod" $Colors.Info
        Write-ColorMessage "3. 如需获取命令帮助，请使用 -Help 参数" $Colors.Info
    } else {
        Write-ColorMessage "1. 如需查询远程计算机，请使用 -ComputerName 参数" $Colors.Info
        Write-ColorMessage "2. 如需获取命令帮助，请使用 -Help 参数" $Colors.Info
        Write-ColorMessage "3. 如需指定凭据，请使用 -Credential 参数" $Colors.Info
    }
    Write-ColorMessage "4. 如需保存到文件，请使用 -SaveToFile 参数" $Colors.Info
    Write-ColorMessage "5. 按任意键退出..." $Colors.Info
    Write-ColorMessage "6. 请勿用鼠标操作本窗口，否则会复制失败" $Colors.Warning
    
    try {
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    catch {
        Start-Sleep -Seconds 2
    }
}