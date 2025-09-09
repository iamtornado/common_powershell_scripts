#Requires -Version 5.1

<#
.SYNOPSIS
    将指定域账户添加到远程Windows计算机的本地Administrators组中

.DESCRIPTION
    此脚本使用传统的基于DCOM的WMI连接到远程计算机，并将指定的域账户添加到本地Administrators组。
    脚本包含网络连通性检测、远程计算机信息收集、错误处理等功能，为IT桌面运维工程师提供决策支持。

.PARAMETER ComputerName
    目标远程计算机的名称或IP地址，可以是短主机名、FQDN，也可以是IP地址

.PARAMETER DomainUser
    要添加到本地Administrators组的域账户名称（格式：DOMAIN\Username 或 Username@domain.com）

.PARAMETER Credential
    用于连接远程计算机的凭据（可选，如果不提供则使用当前用户凭据）

.PARAMETER Force
    强制执行操作，跳过确认提示

.PARAMETER WhatIf
    显示将要执行的操作，但不实际执行

.PARAMETER Confirm
    在执行操作前提示确认

.PARAMETER DebugOutput
    显示详细调试信息

.EXAMPLE
    .\Add-DomainUserToLocalAdmin.ps1 -ComputerName "SERVER01" -DomainUser "CONTOSO\john.doe"

.EXAMPLE
    .\Add-DomainUserToLocalAdmin.ps1 -ComputerName "192.168.1.100" -DomainUser "john.doe@contoso.com" -Credential (Get-Credential)

.EXAMPLE
    .\Add-DomainUserToLocalAdmin.ps1 -ComputerName "SERVER01.contoso.com" -DomainUser "CONTOSO\admin" -Force

.NOTES
    作者: tornadoami
    版本: 3.2
    创建日期: 2025-07-31
    DreamAI官网: https://alidocs.dingtalk.com/i/nodes/Amq4vjg890AlRbA6Td9ZvlpDJ3kdP0wQ?utm_scene=team_space
    要求: PowerShell 5.1+, Windows Management Framework 5.1+
    
    此脚本使用传统的基于DCOM的WMI连接，而不是更现代的WinRM连接。
    确保目标计算机启用了DCOM和WMI服务。

.LINK
    https://github.com/iamtornado/common_powershell_scripts
#>

[CmdletBinding(
    SupportsShouldProcess = $true,
    ConfirmImpact = 'High'
)]
param(
    [Parameter(
        Mandatory = $true,
        Position = 0,
        HelpMessage = "目标远程计算机的名称或IP地址"
    )]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName,

    [Parameter(
        Mandatory = $true,
        Position = 1,
        HelpMessage = "要添加到本地Administrators组的域账户名称"
    )]
    [ValidateNotNullOrEmpty()]
    [string]$DomainUser,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "用于连接远程计算机的凭据"
    )]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(
        Mandatory = $false,
        HelpMessage = "强制执行操作，跳过确认提示"
    )]
    [switch]$Force,
    
    [Parameter(
        Mandatory = $false,
        HelpMessage = "显示详细调试信息"
    )]
    [switch]$DebugOutput
)

# 设置错误处理
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# 脚本开始时间
$ScriptStartTime = Get-Date



# 函数：判断是否为IP地址
function Test-IPAddress {
    param([string]$Address)
    
    # 使用正则表达式检查是否为IPv4地址
    return $Address -match '^(\d{1,3}\.){3}\d{1,3}$'
}

# 函数：从FQDN提取主机名（不处理IP地址）
function Get-HostNameFromFQDN {
    param([string]$ComputerName)
    
    # 如果是IP地址，直接返回原始值
    if (Test-IPAddress -Address $ComputerName) {
        return $ComputerName
    }
    
    # 如果是FQDN，提取主机名部分
    if ($ComputerName -match '^([^.]+)\.') {
        return $matches[1]
    }
    
    # 否则返回原始值
    return $ComputerName
}

# 函数：安全的WMI查询包装器
function Invoke-WmiQuery {
    param(
        [string]$Class,
        [string]$Query,
        [string]$ComputerName,
        [string]$Filter,
        [System.Management.Automation.PSCredential]$Credential,
        [switch]$ErrorActionStop
    )
    
    try {
        $params = @{}
        if ($Class) { $params['Class'] = $Class }
        if ($Query) { $params['Query'] = $Query }
        if ($ComputerName) { $params['ComputerName'] = $ComputerName }
        if ($Filter) { $params['Filter'] = $Filter }
        if ($Credential) { $params['Credential'] = $Credential }
        if ($ErrorActionStop) { 
            $params['ErrorAction'] = 'Stop' 
        } else {
            $params['ErrorAction'] = 'SilentlyContinue'
        }
        
        # 首次调用可能会触发模块加载
        return Get-WmiObject @params
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        # 如果Get-WmiObject不可用，尝试使用CIM替代
        Write-DebugMessage "Get-WmiObject不可用，尝试使用Get-CimInstance" $Colors.Warning
        
        $cimParams = @{}
        if ($Class) { $cimParams['ClassName'] = $Class }
        if ($Query) { $cimParams['Query'] = $Query }
        if ($ComputerName) { $cimParams['ComputerName'] = $ComputerName }
        if ($Filter) { $cimParams['Filter'] = $Filter }
        if ($ErrorActionStop) { 
            $cimParams['ErrorAction'] = 'Stop' 
        } else {
            $cimParams['ErrorAction'] = 'SilentlyContinue'
        }
        
        # CIM不直接支持PSCredential，需要创建CimSession
        if ($Credential -and $ComputerName) {
            $sessionOption = New-CimSessionOption -Protocol Dcom
            $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption
            $cimParams['CimSession'] = $cimSession
            $cimParams.Remove('ComputerName')
        }
        
        try {
            return Get-CimInstance @cimParams
        }
        finally {
            if ($cimSession) {
                Remove-CimSession -CimSession $cimSession
            }
        }
    }
    catch {
        throw
    }
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

# 函数：输出调试信息（仅在DebugOutput模式下显示）
function Write-DebugMessage {
    param(
        [string]$Message,
        [string]$Color = 'Cyan'
    )
    
    if ($DebugOutput) {
        Write-ColorMessage "  [DEBUG] $Message" $Color
    }
}

# 函数：写入详细日志
function Write-DetailedLog {
    param(
        [string]$Message,
        [string]$Level = 'INFO',
        [hashtable]$AdditionalData = @{}
    )
    
    $logEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        Level = $Level
        Message = $Message
        ComputerName = $ComputerName
        DomainUser = $DomainUser
        ScriptVersion = "3.2"
    }
    
    if ($AdditionalData.Count -gt 0) {
        $logEntry.Add("AdditionalData", $AdditionalData)
    }
    
    $logJson = $logEntry | ConvertTo-Json -Depth 10 -Compress
    $detailedLogFile = Join-Path $PSScriptRoot $ScriptConfig.DetailedLogFile
    Add-Content -Path $detailedLogFile -Value $logJson -Encoding UTF8
}

# 脚本配置设置（内置配置，无需外部文件）
$ScriptConfig = @{
    # 脚本信息
    ScriptName = "Add-DomainUserToLocalAdmin"
    Version = "3.2"
    Author = "tornadoami"
    Description = "将指定域账户添加到远程Windows计算机的本地Administrators组中"
    
    # 超时设置
    DefaultTimeout = 30  # 秒
    ConnectionTimeout = 30  # 秒
    WmiTimeout = 30  # 秒
    
    # 日志设置
    LogEnabled = $true
    LogFile = "Add-DomainUserToLocalAdmin.log"
    DetailedLogFile = "Add-DomainUserToLocalAdmin_Detailed.log"
    
    # 网络设置
    PingTimeout = 1000  # 毫秒
    
    # 安全设置
    MaxAdministratorsMembers = 50  # 最大Administrators组成员数量警告阈值
}

# 颜色定义，用于输出美化
$Colors = @{
    Success = 'Green'
    Warning = 'Yellow'
    Error = 'Red'
    Info = 'Cyan'
    Header = 'Magenta'
}



# 函数：显示脚本头部信息
function Show-ScriptHeader {
    Write-ColorMessage "╔══════════════════════════════════════════════════════════════╗" $Colors.Header
    Write-ColorMessage "║                域账户本地管理员添加工具                    ║" $Colors.Header
    Write-ColorMessage "║            Domain User Local Admin Addition Tool            ║" $Colors.Header
    Write-ColorMessage "╚══════════════════════════════════════════════════════════════╝" $Colors.Header
    Write-Host ""
    Write-ColorMessage "脚本开始时间: $($ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))" $Colors.Info
    Write-ColorMessage "目标计算机: $ComputerName" $Colors.Info
    Write-ColorMessage "目标域账户: $DomainUser" $Colors.Info
    Write-Host ""
    
    Write-DetailedLog "脚本开始执行" "INFO" @{Category = "Initialization"}
}

# 函数：测试网络连通性
function Test-NetworkConnectivity {
    param([string]$TargetComputer)
    
    Write-ColorMessage "正在检测网络连通性..." $Colors.Info
    
    try {
        # 智能提取主机名（区分IP地址和FQDN）
        $hostName = Get-HostNameFromFQDN -ComputerName $TargetComputer
        if ($hostName -ne $TargetComputer) {
            Write-DebugMessage "从FQDN提取主机名: $TargetComputer -> $hostName"
        }
        
        # 首先尝试使用原始名称
        Write-DebugMessage "尝试连接: $TargetComputer"
        $pingResult = Test-Connection -ComputerName $TargetComputer -Count 1 -Quiet -ErrorAction SilentlyContinue
        
        if (-not $pingResult -and $hostName -ne $TargetComputer) {
            # 如果原始名称失败，尝试使用主机名
            Write-DebugMessage "原始名称连接失败，尝试主机名: $hostName"
            $pingResult = Test-Connection -ComputerName $hostName -Count 1 -Quiet -ErrorAction SilentlyContinue
        }
        
        if ($pingResult) {
            Write-ColorMessage "✓ 网络连通性检测成功" $Colors.Success
            Write-DetailedLog "网络连通性检测成功" "INFO" @{Category = "NetworkTest"}
            return $true
        } else {
            Write-ColorMessage "✗ 网络连通性检测失败" $Colors.Error
            Write-DetailedLog "网络连通性检测失败" "ERROR" @{Category = "NetworkTest"}
            return $false
        }
    }
    catch {
        Write-ColorMessage "✗ 网络连通性检测失败: $($_.Exception.Message)" $Colors.Error
        Write-DetailedLog "网络连通性检测失败: $($_.Exception.Message)" "ERROR" @{Category = "NetworkTest"}
        return $false
    }
}

# 函数：验证域账户格式
function Test-DomainUserFormat {
    param([string]$User)
    
    # 检查是否包含反斜杠（DOMAIN\Username格式）
    if ($User -match '\\') {
        return $true
    }
    
    # 检查是否包含@符号（Username@domain.com格式）
    if ($User -match '@') {
        return $true
    }
    
    # 如果都不包含，假设是当前域的账户
    return $true
}

# 函数：获取远程计算机基本信息
function Get-RemoteComputerInfo {
    param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-ColorMessage "正在收集远程计算机信息..." $Colors.Info
    
    try {
        Write-DebugMessage "开始构建WMI连接选项..."
        
        # 确保WMI连接使用正确的计算机名（IP地址保持不变，FQDN提取主机名）
        $wmiComputerName = Get-HostNameFromFQDN -ComputerName $ComputerName
        if ($wmiComputerName -ne $ComputerName) {
            Write-DebugMessage "WMI使用主机名: $ComputerName -> $wmiComputerName"
        }
        
        # 构建WMI连接选项
        $connectionOptions = New-Object System.Management.ConnectionOptions
        if ($Credential) {
            $connectionOptions.Username = $Credential.UserName
            $connectionOptions.Password = $Credential.GetNetworkCredential().Password
        }
        $connectionOptions.Impersonation = [System.Management.ImpersonationLevel]::Impersonate
        $connectionOptions.Authentication = [System.Management.AuthenticationLevel]::Default
        $connectionOptions.Timeout = New-Object System.TimeSpan(0, 0, $ScriptConfig.ConnectionTimeout)
        
        Write-DebugMessage "正在连接到远程计算机..."
        # 连接到远程计算机
        $scope = New-Object System.Management.ManagementScope("\\$wmiComputerName\root\cimv2", $connectionOptions)
        $scope.Connect()
        
        Write-ColorMessage "✓ 成功连接到远程计算机: $ComputerName" $Colors.Success
        Write-DetailedLog "成功连接到远程计算机: $ComputerName" "INFO" @{Category = "WmiConnection"}
        
        Write-DebugMessage "正在获取计算机系统信息..."
        # 获取计算机系统信息
        $computerSystem = Invoke-WmiQuery -Class Win32_ComputerSystem -ComputerName $wmiComputerName -Credential $Credential
        
        Write-DebugMessage "正在获取操作系统信息..."
        # 获取操作系统信息
        $operatingSystem = Invoke-WmiQuery -Class Win32_OperatingSystem -ComputerName $wmiComputerName -Credential $Credential
        
        Write-DebugMessage "正在获取网络配置信息..."
        # 获取网络配置信息
        $networkConfig = Invoke-WmiQuery -Class Win32_NetworkAdapterConfiguration -ComputerName $wmiComputerName -Credential $Credential -Filter "IPEnabled = 'True'"
        
        # 获取本地计算机名（用于本地组过滤）
        # $localComputerName = $computerSystem
        
        Write-DebugMessage "正在获取本地Administrators组成员..."
        # 获取本地Administrators组成员（高效写法，避免枚举全系统）
        $groupName = "Administrators"
        
        # 解析计算机名称，如果是IP地址则获取实际主机名
        $resolvedComputerName = $ComputerName
        if (Test-IPAddress -Address $ComputerName) {
            try {
                Write-DebugMessage "检测到IP地址，正在解析主机名..."
                $resolvedComputerName = [System.Net.Dns]::GetHostEntry($ComputerName).HostName
                Write-DebugMessage "IP地址 $ComputerName 解析为主机名: $resolvedComputerName"
            } catch {
                Write-DebugMessage "无法解析IP地址 $ComputerName 的主机名，将使用IP地址: $($_.Exception.Message)" $Colors.Warning
                $resolvedComputerName = $ComputerName
            }
        }
        
        $groupDomain = $resolvedComputerName.Split(".")[0]  # 取主机名作为本地组的Domain
        Write-DebugMessage "使用组Domain: '$groupDomain', 组名: '$groupName'"
        
        # 获取组对象（可选校验）
        # $adminGroup = Get-WmiObject -Class Win32_Group -ComputerName $ComputerName -Credential $Credential `
        #     -Filter "Name='$groupName' AND Domain='$groupDomain'" -ErrorAction Stop
        
        # 查询组成员（使用ASSOCIATORS OF查询）
        Write-DebugMessage "执行WMI查询获取Administrators组成员..."
        $adminMembersQuery = "ASSOCIATORS OF {Win32_Group.Domain='$groupDomain',Name='$groupName'} WHERE AssocClass=Win32_GroupUser Role=GroupComponent"
        Write-DebugMessage "执行WMI查询: $adminMembersQuery"
        $adminMembers = Invoke-WmiQuery -Query $adminMembersQuery -ComputerName $wmiComputerName -Credential $Credential
        Write-DebugMessage "成功获取到 $($adminMembers.Count) 个Administrators组成员"
        
        
        Write-DebugMessage "正在获取当前交互式登录用户..."
        # 获取当前交互式登录用户（只显示真实登录桌面用户）
        $users = @()
        Write-DebugMessage "正在获取登录会话..."
        $logonSessions = Invoke-WmiQuery -Class Win32_LogonSession -ComputerName $wmiComputerName -Credential $Credential |
            Where-Object { $_.LogonType -eq 2 -or $_.LogonType -eq 10 } # 2: 交互式, 10: 远程交互式
        Write-DebugMessage "找到 $($logonSessions.Count) 个交互式登录会话"
        
        foreach ($session in $logonSessions) {
            $logonId = $session.LogonId
            Write-DebugMessage "处理登录会话 LogonId: $logonId"
            $assocs = Invoke-WmiQuery -Class Win32_LoggedOnUser -ComputerName $wmiComputerName -Credential $Credential |
                Where-Object { $_.Dependent -match "LogonId=`"$logonId`"" }
            Write-DebugMessage "找到 $($assocs.Count) 个关联用户"
            
            foreach ($assoc in $assocs) {
                try {
                    Write-DebugMessage "解析用户路径: $($assoc.Antecedent)"
                                         # 改进的用户解析逻辑，支持本地用户和域用户
                     if ($assoc.Antecedent -match 'Win32_UserAccount\.Domain="([^"]+)",Name="([^"]+)"') {
                         $userDomain = $matches[1]
                         $userName = $matches[2]
                         $fullName = "$userDomain\$userName"
                         $userNameOnly = $userName
                         if ($userNameOnly -notmatch '^(DWM-|UMFD-|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|IUSR_|IWAM_|DefaultAccount|Guest|Administrator\$)' -and $users -notcontains $fullName) {
                             $users += $fullName
                             Write-DebugMessage "添加用户: $fullName"
                         } else {
                             Write-DebugMessage "过滤系统账户: $fullName"
                         }
                     } elseif ($assoc.Antecedent -match 'Win32_Group\.Domain="([^"]+)",Name="([^"]+)"') {
                         $userDomain = $matches[1]
                         $userName = $matches[2]
                         $fullName = "$userDomain\$userName"
                         $userNameOnly = $userName
                         if ($userNameOnly -notmatch '^(DWM-|UMFD-|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|IUSR_|IWAM_|DefaultAccount|Guest|Administrator\$)' -and $users -notcontains $fullName) {
                             $users += $fullName
                             Write-DebugMessage "添加用户: $fullName"
                         } else {
                             Write-DebugMessage "过滤系统账户: $fullName"
                         }
                     } elseif ($assoc.Antecedent -match 'Win32_Account\.Domain="([^"]+)",Name="([^"]+)"') {
                         # 新增：处理Win32_Account格式
                         $userDomain = $matches[1]
                         $userName = $matches[2]
                         $fullName = "$userDomain\$userName"
                         $userNameOnly = $userName
                         if ($userNameOnly -notmatch '^(DWM-|UMFD-|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|IUSR_|IWAM_|DefaultAccount|Guest|Administrator\$)' -and $users -notcontains $fullName) {
                             $users += $fullName
                             Write-DebugMessage "添加用户: $fullName"
                         } else {
                             Write-DebugMessage "过滤系统账户: $fullName"
                         }
                    } else {
                        Write-DebugMessage "无法解析用户路径格式: $($assoc.Antecedent)" $Colors.Warning
                    }
                } catch {
                    # 优化错误处理：只记录真正的错误，忽略系统虚拟账户的解析失败
                    if ($assoc.Antecedent -match 'DWM-|UMFD-|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|IUSR_|IWAM_|DefaultAccount|Guest|Administrator\$') {
                        Write-DebugMessage "忽略系统虚拟账户解析: $($assoc.Antecedent)" $Colors.Warning
                    } else {
                        Write-DebugMessage "忽略解析失败的对象: $($_.Exception.Message)" $Colors.Warning
                    }
                }
            }
        }
        Write-DebugMessage "最终找到 $($users.Count) 个有效登录用户"
        
        # 安全地转换LastBootTime
        $lastBootTime = Get-Date
        try {
            if ($operatingSystem.LastBootUpTime -and $operatingSystem.LastBootUpTime -ne "-") {
                $lastBootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($operatingSystem.LastBootUpTime)
            }
        } catch {
            Write-DebugMessage "无法解析LastBootUpTime，使用当前时间: $($_.Exception.Message)"
        }
        
        # 使用ADSI查询获取本地Administrators组成员（替代WMI方法）
        Write-DebugMessage "正在使用ADSI查询获取本地Administrators组成员..."
        $adminMembersList = @()
        
        try {
            # 确保使用正确的主机名构建ADSI路径
            $adsComputerName = Get-HostNameFromFQDN -ComputerName $resolvedComputerName
            if ($adsComputerName -ne $resolvedComputerName) {
                Write-DebugMessage "ADSI使用主机名: $resolvedComputerName -> $adsComputerName"
            }
            
            # 构建ADSI路径连接到远程计算机的本地Administrators组
            $groupPath = "WinNT://$adsComputerName/Administrators,group"
            Write-DebugMessage "ADSI路径: $groupPath"
            
            $group = [ADSI]$groupPath
            Write-DebugMessage "成功连接到远程计算机的Administrators组对象"
            
            foreach ($member in $group.Members()) {
                try {
                    $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                    $memberPath = $member.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $member, $null)
                    
                    Write-DebugMessage "成员ADsPath: $memberPath"
                    
                    # 从ADsPath解析域名和用户名
                    # 处理三段式路径：WinNT://DOMAIN/COMPUTER/USER
                    if ($memberPath -match 'WinNT://([^/]+)/([^/]+)/([^/]+)') {
                        # $part1 = $matches[1]  # 域名部分，暂时不需要使用
                        $part2 = $matches[2]
                        $part3 = $matches[3]
                        
                        # 三段式路径通常是本地用户：WinNT://DOMAIN/COMPUTER/USER
                        # 其中COMPUTER是实际的计算机名，USER是本地用户名
                        if ($part2 -eq $adsComputerName -or $part2 -eq $adsComputerName.ToUpper()) {
                            $fullMemberName = "$part2\$part3"
                            Write-DebugMessage "解析本地用户: Computer=$part2, User=$part3, 完整名称=$fullMemberName"
                        } else {
                            # 不常见的情况，保留原始格式
                            $fullMemberName = "$part2\$part3"
                            Write-DebugMessage "解析成员（三段式）: $memberPath -> $fullMemberName"
                        }
                        
                        $adminMembersList += $fullMemberName
                    }
                    # 处理两段式路径：WinNT://DOMAIN/USER 或 WinNT://COMPUTER/USER
                    elseif ($memberPath -match 'WinNT://([^/]+)/([^/]+)') {
                        $memberDomain = $matches[1]
                        $memberUserName = $matches[2]
                        
                        # 判断是本地用户还是域用户/组
                        if ($memberDomain -eq $adsComputerName -or $memberDomain -eq $adsComputerName.ToUpper()) {
                            # 本地用户/组，使用计算机名作为域名
                            $fullMemberName = "$adsComputerName\$memberUserName"
                            Write-DebugMessage "解析本地用户: Computer=$memberDomain, User=$memberUserName, 完整名称=$fullMemberName"
                        } else {
                            # 域用户/组，使用实际域名
                            $fullMemberName = "$memberDomain\$memberUserName"
                            Write-DebugMessage "解析域用户/组: Domain=$memberDomain, Name=$memberUserName, 完整名称=$fullMemberName"
                        }
                        
                        $adminMembersList += $fullMemberName
                    } else {
                        Write-DebugMessage "无法解析ADsPath格式: $memberPath，原始路径已加入列表" $Colors.Warning
                        $adminMembersList += $memberPath
                    }
                } catch {
                    Write-DebugMessage "解析成员时出错: $($_.Exception.Message)" $Colors.Warning
                }
            }
            
            Write-DebugMessage "ADSI查询成功，获取到 $($adminMembersList.Count) 个成员"
            Write-DebugMessage "最终成员列表: $($adminMembersList -join ', ')"
            
        } catch {
            Write-DebugMessage "ADSI查询失败，回退到WMI方法: $($_.Exception.Message)" $Colors.Warning
            
            # 回退到WMI方法
            $adminMembersQuery = "ASSOCIATORS OF {Win32_Group.Domain='$groupDomain',Name='$groupName'} WHERE AssocClass=Win32_GroupUser Role=GroupComponent"
            
            Write-DebugMessage "回退WMI查询: $adminMembersQuery"
            $adminMembers = Invoke-WmiQuery -Query $adminMembersQuery -ComputerName $wmiComputerName -ErrorActionStop:$false
            
            if ($adminMembers) {
                Write-DebugMessage "WMI返回成员数量: $($adminMembers.Count)"
                foreach ($member in $adminMembers) {
                    try {
                        $memberDomain = $member.Domain
                        $memberName = $member.Name
                        $fullMemberName = "$memberDomain\$memberName"
                        Write-DebugMessage "WMI成员信息: Domain=$memberDomain, Name=$memberName, 完整名称=$fullMemberName"
                        $adminMembersList += $fullMemberName
                    } catch {
                        Write-DebugMessage "WMI解析成员时出错: $($_.Exception.Message)" $Colors.Warning
                    }
                }
            } else {
                Write-DebugMessage "WMI查询也失败，无法获取Administrators组成员" $Colors.Warning
            }
        }
        
        # 构建返回对象
        $computerInfo = [PSCustomObject]@{
            ComputerName = $computerSystem.Name
            Domain = $computerSystem.Domain
            Workgroup = $computerSystem.Workgroup
            OperatingSystem = $operatingSystem.Caption
            OSVersion = $operatingSystem.Version
            IPAddresses = @($networkConfig | ForEach-Object { $_.IPAddress } | Where-Object { $_ -and $_ -ne "0.0.0.0" })
            LoggedOnUsers = $users
            AdministratorsMembers = $adminMembersList
            LastBootTime = $lastBootTime
            TotalPhysicalMemory = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
        }
        
        Write-DetailedLog "成功收集远程计算机信息" "INFO" @{Category = "InfoCollection"}
        
        return $computerInfo
    }
    catch {
        Write-ColorMessage "✗ 获取远程计算机信息失败: $($_.Exception.Message)" $Colors.Error
        Write-DetailedLog "获取远程计算机信息失败: $($_.Exception.Message)" "ERROR" @{Category = "InfoCollection"}
        throw
    }
}

# 函数：显示远程计算机信息
function Show-RemoteComputerInfo {
    param([PSCustomObject]$ComputerInfo)
    
    Write-ColorMessage "╔══════════════════════════════════════════════════════════════╗" $Colors.Header
    Write-ColorMessage "║                    远程计算机信息                          ║" $Colors.Header
    Write-ColorMessage "╚══════════════════════════════════════════════════════════════╝" $Colors.Header
    
    Write-ColorMessage "计算机名称: $($ComputerInfo.ComputerName)" $Colors.Info
    Write-ColorMessage "域/工作组: $($ComputerInfo.Domain)$(if($ComputerInfo.Workgroup){' / '+$ComputerInfo.Workgroup})" $Colors.Info
    Write-ColorMessage "操作系统: $($ComputerInfo.OperatingSystem)" $Colors.Info
    Write-ColorMessage "系统版本: $($ComputerInfo.OSVersion)" $Colors.Info
    Write-ColorMessage "IP地址: $($ComputerInfo.IPAddresses -join ', ')" $Colors.Info
    Write-ColorMessage "总内存: $($ComputerInfo.TotalPhysicalMemory) GB" $Colors.Info
    if ($ComputerInfo.LastBootTime -and $ComputerInfo.LastBootTime -ne [DateTime]::MinValue) {
        Write-ColorMessage "最后启动时间: $($ComputerInfo.LastBootTime.ToString('yyyy-MM-dd HH:mm:ss'))" $Colors.Info
    } else {
        Write-ColorMessage "最后启动时间: 无法获取" $Colors.Warning
    }
    
    Write-ColorMessage "当前登录用户:" $Colors.Info
    if ($ComputerInfo.LoggedOnUsers.Count -gt 0) {
        foreach ($user in $ComputerInfo.LoggedOnUsers) {
            Write-ColorMessage "  - $user" $Colors.Info
        }
    } else {
        Write-ColorMessage "  - 无用户登录" $Colors.Warning
    }
    
    Write-ColorMessage "本地Administrators组成员:" $Colors.Info
    if ($ComputerInfo.AdministratorsMembers.Count -gt 0) {
        foreach ($member in $ComputerInfo.AdministratorsMembers) {
            Write-ColorMessage "  - $member" $Colors.Info
        }
    } else {
        Write-ColorMessage "  - 无成员" $Colors.Warning
    }
    
    Write-Host ""
}

# 函数：检查域账户是否已经是Administrators组成员
function Test-UserInAdministratorsGroup {
    param(
        [string]$DomainUser,
        [string[]]$AdminMembersList
    )
    foreach ($member in $AdminMembersList) {
        Write-DebugMessage "比对成员: $member <-> 目标: $DomainUser"
        if ($member -ieq $DomainUser) {
            Write-DebugMessage "完全匹配: $member"
            return $true
        }
        # 兼容只比对用户名部分
        if ($DomainUser -match '\\') {
            $parts = $DomainUser -split '\\', 2
            $userDomain = $parts[0]
            $userName = $parts[1]
            if ($member -match '\\') {
                $mParts = $member -split '\\', 2
                if ($mParts[0] -ieq $userDomain -and $mParts[1] -ieq $userName) {
                    Write-DebugMessage "域和用户名部分匹配: $member"
                    return $true
                }
            }
        }
    }
    Write-DebugMessage "未找到匹配成员: $DomainUser"
    return $false
}

# 函数：使用WMI方法添加域账户到本地Administrators组（备用方法）
function Add-DomainUserToAdministratorsGroupWMI {
    param(
        [string]$ComputerName,
        [string]$DomainUser,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        Write-ColorMessage "正在使用WMI方法添加用户..." $Colors.Info
        Write-DetailedLog "开始使用WMI方法添加域账户到Administrators组: $DomainUser" "INFO" @{Category = "UserAdditionWMI"}
        
        # 解析域用户信息
        $domain = ""
        $username = ""
        
        if ($DomainUser -match '\\') {
            $parts = $DomainUser -split '\\', 2
            $domain = $parts[0]
            $username = $parts[1]
        } elseif ($DomainUser -match '@') {
            $parts = $DomainUser -split '@', 2
            $username = $parts[0]
            $domain = $parts[1].Split('.')[0]
        } else {
            $domain = $env:USERDOMAIN
            $username = $DomainUser
        }
        
        Write-DebugMessage "WMI方法解析结果 - 域: $domain, 用户名: $username"
        
        # 确保使用正确的主机名
        $wmiComputerName = Get-HostNameFromFQDN -ComputerName $ComputerName
        if ($wmiComputerName -ne $ComputerName) {
            Write-DebugMessage "WMI使用主机名: $ComputerName -> $wmiComputerName"
        }
        
        # 获取本地Administrators组
        $adminGroup = Invoke-WmiQuery -Class Win32_Group -ComputerName $wmiComputerName -Credential $Credential -Filter "Name='Administrators' AND LocalAccount=True"
        
        if (-not $adminGroup) {
            throw "无法找到本地Administrators组"
        }
        
        Write-DebugMessage "找到Administrators组: $($adminGroup.Name)"
        
        # 使用WMI的Add方法添加用户到组
        $result = $adminGroup.Add("WinNT://$domain/$username")
        
        if ($result.ReturnValue -eq 0) {
            Write-ColorMessage "✓ WMI方法成功将域账户 '$DomainUser' 添加到本地Administrators组" $Colors.Success
            Write-DetailedLog "WMI方法成功添加域账户到Administrators组: $DomainUser" "INFO" @{Category = "UserAdditionWMI"}
            return $true
        } else {
            $errorMsg = "WMI Add方法返回错误代码: $($result.ReturnValue)"
            Write-ColorMessage "✗ $errorMsg" $Colors.Error
            Write-DetailedLog "WMI Add方法失败: $errorMsg" "ERROR" @{Category = "UserAdditionWMI"}
            return $false
        }
    }
    catch {
        Write-ColorMessage "✗ WMI方法执行失败: $($_.Exception.Message)" $Colors.Error
        Write-DetailedLog "WMI方法执行失败: $($_.Exception.Message)" "ERROR" @{Category = "UserAdditionWMI"}
        throw
    }
}

# 函数：添加域账户到本地Administrators组
function Add-DomainUserToAdministratorsGroup {
    param(
        [string]$ComputerName,
        [string]$DomainUser,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    
    try {
        Write-ColorMessage "正在添加域账户到本地Administrators组..." $Colors.Info
        Write-DetailedLog "开始添加域账户到Administrators组: $DomainUser" "INFO" @{Category = "UserAddition"}
        
        # 解析域用户信息
        $domain = ""
        $username = ""
        
        if ($DomainUser -match '\\') {
            # DOMAIN\Username 格式
            $parts = $DomainUser -split '\\', 2
            $domain = $parts[0]
            $username = $parts[1]
        } elseif ($DomainUser -match '@') {
            # Username@domain.com 格式
            $parts = $DomainUser -split '@', 2
            $username = $parts[0]
            $domain = $parts[1].Split('.')[0]  # 取域名部分
        } else {
            # 假设是当前域的用户
            $domain = $env:USERDOMAIN
            $username = $DomainUser
        }
        
        Write-DebugMessage "解析结果 - 域: $domain, 用户名: $username"
        Write-DetailedLog "解析域用户信息 - 域: $domain, 用户名: $username" "INFO" @{Category = "UserAddition"}
        
        # 使用ADSI方法添加用户到本地组（在本地执行）
        Write-ColorMessage "正在使用ADSI方法添加用户..." $Colors.Info
        try {
            # 确保使用正确的主机名构建ADSI路径
            $adsComputerName = Get-HostNameFromFQDN -ComputerName $ComputerName
            if ($adsComputerName -ne $ComputerName) {
                Write-DebugMessage "ADSI使用主机名: $ComputerName -> $adsComputerName"
            }
            
            # 构建远程 Administrators 组对象的 ADSI 路径
            $groupPath = "WinNT://$adsComputerName/Administrators,group"
            Write-DebugMessage "组路径: $groupPath"
            
            # 构建要添加用户的 ADSI 路径
            # 对于域用户，使用正确的ADSI路径格式
            if ($Domain -and $Username) {
                # 根据你的环境，域是 mywind，使用最直接的路径格式
                # 不添加 ,user 后缀，这通常会导致路径错误
                $userPath = "WinNT://$Domain/$Username"
                Write-DebugMessage "使用用户路径: $userPath"
            } else {
                throw "无法解析域用户信息：域='$Domain', 用户名='$Username'"
            }
            
            # 获取组对象
            $groupObj = [ADSI]$groupPath
            
            # 获取用户对象
            $userObj = [ADSI]$userPath
            
            # 添加用户到组
            $groupObj.Add($userObj.Path)
            
            Write-ColorMessage "✓ 成功将域账户 '$DomainUser' 添加到本地Administrators组" $Colors.Success
            Write-DetailedLog "成功添加域账户到Administrators组: $DomainUser" "INFO" @{Category = "UserAddition"}
            return $true
        }
        catch {
            Write-ColorMessage "✗ ADSI方法执行失败: $($_.Exception.Message)" $Colors.Error
            Write-DetailedLog "ADSI方法执行失败: $($_.Exception.Message)" "ERROR" @{Category = "UserAddition"}
            
            # 如果ADSI方法失败，尝试使用WMI方法作为备用
            Write-ColorMessage "尝试使用WMI方法作为备用..." $Colors.Warning
            try {
                return Add-DomainUserToAdministratorsGroupWMI -ComputerName $ComputerName -DomainUser $DomainUser -Credential $Credential
            } catch {
                Write-ColorMessage "✗ WMI备用方法也失败: $($_.Exception.Message)" $Colors.Error
                return $false
            }
        }
    }
    catch {
        Write-ColorMessage "✗ 添加用户到Administrators组失败: $($_.Exception.Message)" $Colors.Error
        Write-DetailedLog "添加用户到Administrators组失败: $($_.Exception.Message)" "ERROR" @{Category = "UserAddition"}
        throw
    }
}

# 函数：验证操作结果
function Test-OperationResult {
    param(
        [string]$ComputerName,
        [string]$DomainUser,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    
    try {
        Write-ColorMessage "正在验证操作结果..." $Colors.Info
        Write-DetailedLog "开始验证操作结果: $DomainUser" "INFO" @{Category = "Verification"}
        
        # 等待一小段时间让更改生效
        Start-Sleep -Seconds 2
        
        # 重新获取最新的Administrators组成员列表
        Write-DebugMessage "重新获取Administrators组成员列表以验证操作结果..."
        
        # 确保使用正确的计算机名进行验证查询
        $verifyComputerName = Get-HostNameFromFQDN -ComputerName $ComputerName
        if ($verifyComputerName -ne $ComputerName) {
            Write-DebugMessage "验证时使用主机名: $ComputerName -> $verifyComputerName"
        }
        
        $adminMembersList = @()
        try {
            # 使用ADSI获取最新的成员列表
            $groupPath = "WinNT://$verifyComputerName/Administrators,group"
            Write-DebugMessage "验证ADSI路径: $groupPath"
            
            $group = [ADSI]$groupPath
            Write-DebugMessage "成功连接到Administrators组对象进行验证"
            
            foreach ($member in $group.Members()) {
                try {
                    $memberPath = $member.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $member, $null)
                    Write-DebugMessage "验证成员ADsPath: $memberPath"
                    
                    # 从ADsPath解析域名和用户名
                    # 处理三段式路径：WinNT://DOMAIN/COMPUTER/USER
                    if ($memberPath -match 'WinNT://([^/]+)/([^/]+)/([^/]+)') {
                        # $part1 = $matches[1]  # 域名部分，暂时不需要使用
                        $part2 = $matches[2]
                        $part3 = $matches[3]
                        
                        if ($part2 -eq $verifyComputerName -or $part2 -eq $verifyComputerName.ToUpper()) {
                            $fullMemberName = "$part2\$part3"
                        } else {
                            $fullMemberName = "$part2\$part3"
                        }
                        $adminMembersList += $fullMemberName
                    }
                    # 处理两段式路径：WinNT://DOMAIN/USER
                    elseif ($memberPath -match 'WinNT://([^/]+)/([^/]+)') {
                        $memberDomain = $matches[1]
                        $memberUserName = $matches[2]
                        
                        if ($memberDomain -eq $verifyComputerName -or $memberDomain -eq $verifyComputerName.ToUpper()) {
                            $fullMemberName = "$verifyComputerName\$memberUserName"
                        } else {
                            $fullMemberName = "$memberDomain\$memberUserName"
                        }
                        $adminMembersList += $fullMemberName
                    }
                } catch {
                    Write-DebugMessage "验证时解析成员出错: $($_.Exception.Message)" $Colors.Warning
                }
            }
            
            Write-DebugMessage "验证时获取到 $($adminMembersList.Count) 个成员"
            Write-DebugMessage "验证成员列表: $($adminMembersList -join ', ')"
            
        } catch {
            Write-DebugMessage "ADSI验证查询失败: $($_.Exception.Message)" $Colors.Warning
            Write-ColorMessage "✗ 无法重新获取Administrators组成员列表进行验证" $Colors.Error
            return $false
        }
        
        # 使用最新的成员列表进行验证
        $isMember = Test-UserInAdministratorsGroup -DomainUser $DomainUser -AdminMembersList $adminMembersList
        
        if ($isMember) {
            Write-ColorMessage "✓ 验证成功: 域账户 '$DomainUser' 现在是本地Administrators组成员" $Colors.Success
            Write-DetailedLog "验证成功: 域账户现在是Administrators组成员: $DomainUser" "INFO" @{Category = "Verification"}
            return $true
        } else {
            Write-ColorMessage "✗ 验证失败: 域账户 '$DomainUser' 未能成功添加到本地Administrators组" $Colors.Error
            Write-DetailedLog "验证失败: 域账户未能成功添加到Administrators组: $DomainUser" "ERROR" @{Category = "Verification"}
            return $false
        }
    }
    catch {
        Write-ColorMessage "✗ 验证操作结果失败: $($_.Exception.Message)" $Colors.Error
        Write-DetailedLog "验证操作结果失败: $($_.Exception.Message)" "ERROR" @{Category = "Verification"}
        return $false
    }
}

# 函数：记录操作日志
function Write-OperationLog {
    param(
        [string]$ComputerName,
        [string]$DomainUser,
        [bool]$Success,
        [string]$ErrorMessage = ""
    )
    
    $logEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName = $ComputerName
        DomainUser = $DomainUser
        Success = $Success
        ErrorMessage = $ErrorMessage
        ExecutedBy = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    
    $logFile = Join-Path $PSScriptRoot $ScriptConfig.LogFile
    $logEntry | ConvertTo-Json -Compress | Out-File -FilePath $logFile -Append -Encoding UTF8
}

# 主执行逻辑
try {
    # 显示脚本头部
    Show-ScriptHeader
        # 确保WMI相关模块已加载（解决PowerShell 7中的兼容性问题）
    try {
        # 尝试触发WMI模块的加载
        Write-DebugMessage "尝试触发WMI模块的加载"
        $null = Get-WmiObject -Class Win32_ComputerSystem -ComputerName localhost
    } catch {
        # 忽略错误，这只是为了触发模块加载
    }
    # 验证参数
    if (-not (Test-DomainUserFormat -User $DomainUser)) {
        throw "域账户格式无效。请使用 'DOMAIN\Username' 或 'Username@domain.com' 格式。"
    }
    
    # 测试网络连通性
    if (-not (Test-NetworkConnectivity -TargetComputer $ComputerName)) {
        throw "无法连接到目标计算机 '$ComputerName'。请检查网络连接和计算机名称。"
    }
    
    # 获取远程计算机信息
    $computerInfo = Get-RemoteComputerInfo -ComputerName $ComputerName -Credential $Credential
    
    # 显示远程计算机信息
    Show-RemoteComputerInfo -ComputerInfo $computerInfo
    
    # 检查用户是否已经是Administrators组成员
    $isAlreadyMember = Test-UserInAdministratorsGroup -DomainUser $DomainUser -AdminMembersList $computerInfo.AdministratorsMembers
    
    if ($isAlreadyMember) {
        Write-ColorMessage "⚠ 域账户 '$DomainUser' 已经是本地Administrators组成员" $Colors.Warning
        if (-not $Force) {
            $continue = Read-Host "是否继续操作？(Y/N)"
            if ($continue -notmatch '^[Yy]') {
                Write-ColorMessage "操作已取消" $Colors.Info
                exit 0
            }
        }
    }
    
    # 显示即将执行的操作信息
    Write-ColorMessage "即将执行的操作:" $Colors.Warning
    Write-ColorMessage "  目标计算机: $ComputerName" $Colors.Warning
    Write-ColorMessage "  实际计算机名: $($computerInfo.ComputerName)" $Colors.Warning
    Write-ColorMessage "  实际IP地址: $($computerInfo.IPAddresses -join ', ')" $Colors.Warning
    Write-ColorMessage "  域/工作组: $($computerInfo.Domain)" $Colors.Warning
    Write-ColorMessage "  操作系统: $($computerInfo.OperatingSystem)" $Colors.Warning
    Write-ColorMessage "  当前登录用户: $($computerInfo.LoggedOnUsers -join ', ')" $Colors.Warning
    Write-ColorMessage "  目标域账户: $DomainUser" $Colors.Warning
    Write-ColorMessage "  操作类型: 添加到本地Administrators组" $Colors.Warning
    Write-ColorMessage "  当前组成员数: $($computerInfo.AdministratorsMembers.Count)" $Colors.Warning
    Write-Host ""
    
    # 确认操作（仅在非强制模式下）
    if (-not $Force) {
        $confirm = Read-Host "确认执行此操作？(Y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-ColorMessage "操作已取消" $Colors.Info
            exit 0
        }
    } else {
        Write-ColorMessage "使用强制模式，跳过确认..." $Colors.Info
    }
    
    # 执行添加操作
    # 如果使用Force参数，直接执行操作，跳过ShouldProcess确认
    if ($Force) {
        Write-ColorMessage "正在执行操作（强制模式）..." $Colors.Info
        $addResult = Add-DomainUserToAdministratorsGroup -ComputerName $ComputerName -DomainUser $DomainUser -Credential $Credential
        
        if ($addResult) {
            # 验证操作结果
            $verifyResult = Test-OperationResult -ComputerName $ComputerName -DomainUser $DomainUser -Credential $Credential
            
            if ($verifyResult) {
                Write-ColorMessage "╔══════════════════════════════════════════════════════════════╗" $Colors.Success
                Write-ColorMessage "║                        操作成功完成                          ║" $Colors.Success
                Write-ColorMessage "╚══════════════════════════════════════════════════════════════╝" $Colors.Success
                
                # 记录成功日志
                Write-OperationLog -ComputerName $ComputerName -DomainUser $DomainUser -Success $true
            } else {
                throw "操作验证失败"
            }
        } else {
            throw "添加用户到Administrators组失败"
        }
    } else {
        # 正常模式，使用ShouldProcess确认
        if ($PSCmdlet.ShouldProcess("$ComputerName", "添加域账户 '$DomainUser' 到本地Administrators组")) {
            $addResult = Add-DomainUserToAdministratorsGroup -ComputerName $ComputerName -DomainUser $DomainUser -Credential $Credential
            
            if ($addResult) {
                # 验证操作结果
                $verifyResult = Test-OperationResult -ComputerName $ComputerName -DomainUser $DomainUser -Credential $Credential
                
                if ($verifyResult) {
                    Write-ColorMessage "╔══════════════════════════════════════════════════════════════╗" $Colors.Success
                    Write-ColorMessage "║                        操作成功完成                          ║" $Colors.Success
                    Write-ColorMessage "╚══════════════════════════════════════════════════════════════╝" $Colors.Success
                    
                    # 记录成功日志
                    Write-OperationLog -ComputerName $ComputerName -DomainUser $DomainUser -Success $true
                } else {
                    throw "操作验证失败"
                }
            } else {
                throw "添加用户到Administrators组失败"
            }
        }
    }
}
catch {
    Write-ColorMessage "╔══════════════════════════════════════════════════════════════╗" $Colors.Error
    Write-ColorMessage "║                        操作失败                            ║" $Colors.Error
    Write-ColorMessage "╚══════════════════════════════════════════════════════════════╝" $Colors.Error
    
    Write-ColorMessage "错误详情: $($_.Exception.Message)" $Colors.Error
    Write-ColorMessage "错误位置: $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" $Colors.Error
    
    # 记录失败日志
    Write-OperationLog -ComputerName $ComputerName -DomainUser $DomainUser -Success $false -ErrorMessage $_.Exception.Message
    
    exit 1
}
finally {
    $ScriptEndTime = Get-Date
    $Duration = $ScriptEndTime - $ScriptStartTime
    
    Write-Host ""
    Write-ColorMessage "脚本结束时间: $($ScriptEndTime.ToString('yyyy-MM-dd HH:mm:ss'))" $Colors.Info
    Write-ColorMessage "脚本执行时长: $($Duration.TotalSeconds.ToString('F2')) 秒" $Colors.Info
    
    Write-DetailedLog "脚本执行完成，总时长: $($Duration.TotalSeconds.ToString('F2')) 秒" "INFO" @{Category = "Completion"}
    Write-Host ""
} 
