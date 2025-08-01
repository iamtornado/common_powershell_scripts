<#
.SYNOPSIS
    查询本地和远程Windows计算机的基本信息脚本

.DESCRIPTION
    此脚本可以查询本地或远程Windows计算机的基本信息，包括：
    - 计算机名（FQDN）
    - IP地址和MAC地址  
    - DNS设置
    - 当前登录用户
    - 本地administrators组成员
    
    对于本地查询使用高效的本地方法，对于远程查询使用基于DCOM的WMI和ADSI。
    查询结果会自动复制到剪切板中。

.PARAMETER IPAddress
    要查询的计算机IP地址。如果不指定，则查询本地计算机。

.PARAMETER OutputDebug
    开启详细调试信息输出。

.EXAMPLE
    .\Get-ComputerBasicInfo.ps1
    查询本地计算机信息

.EXAMPLE
    .\Get-ComputerBasicInfo.ps1 -IPAddress "192.168.1.100"
    查询远程计算机信息

.EXAMPLE
    .\Get-ComputerBasicInfo.ps1 -IPAddress "192.168.1.100" -OutputDebug
    查询远程计算机信息并显示详细调试信息

.AUTHOR
    Created for efficient Windows system information gathering
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="目标Windows计算机的IP地址")]
    [ValidateScript({
        if ($_ -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
            $true
        } else {
            throw "请输入有效的IP地址格式"
        }
    })]
    [string]$IPAddress,
    
    [Parameter(Mandatory=$false, HelpMessage="显示详细调试信息")]
    [switch]$OutputDebug
)

# 调试信息输出函数
function Write-DebugInfo {
    param([string]$Message)
    if ($OutputDebug) {
        Write-Host "[DEBUG] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message" -ForegroundColor Cyan
    }
}

# 错误信息输出函数
function Write-ErrorInfo {
    param([string]$Message)
    Write-Host "[ERROR] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message" -ForegroundColor Red
}

# 成功信息输出函数
function Write-SuccessInfo {
    param([string]$Message)
    Write-Host "[INFO] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message" -ForegroundColor Green
}

# 检查是否为本地IP地址
function Test-IsLocalIP {
    param([string]$IP)
    
    Write-DebugInfo "检查IP地址 $IP 是否为本地地址"
    
    try {
        # 获取本地所有网络接口的IP地址
        $localIPs = @()
        $localIPs += "127.0.0.1"
        $localIPs += "::1"
        
        # 获取所有网络适配器的IP地址
        $networkAdapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne "WellKnown" }
        foreach ($adapter in $networkAdapters) {
            $localIPs += $adapter.IPAddress
        }
        
        Write-DebugInfo "本地IP地址列表: $($localIPs -join ', ')"
        
        $isLocal = $IP -in $localIPs
        Write-DebugInfo "IP地址 $IP 是否为本地: $isLocal"
        return $isLocal
    }
    catch {
        Write-ErrorInfo "检查本地IP时出错: $($_.Exception.Message)"
        return $false
    }
}

# 获取本地计算机信息（高效方法）
function Get-LocalComputerInfo {
    Write-DebugInfo "开始获取本地计算机信息"
    $info = @{}
    
    try {
        # 获取计算机基本信息
        Write-DebugInfo "获取计算机基本信息"
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $info.ComputerName = $computerSystem.Name
        $info.Domain = $computerSystem.Domain
        $info.FQDN = "$($computerSystem.Name).$($computerSystem.Domain)"
        
        # 获取网络配置信息
        Write-DebugInfo "获取网络配置信息"
        $networkConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        $info.NetworkInterfaces = @()
        
        foreach ($config in $networkConfigs) {
            if ($config.IPAddress) {
                $interface = @{
                    Description = $config.Description
                    IPAddress = $config.IPAddress[0]
                    MACAddress = $config.MACAddress
                    DefaultGateway = if ($config.DefaultIPGateway) { $config.DefaultIPGateway[0] } else { "N/A" }
                    DNSServers = if ($config.DNSServerSearchOrder) { $config.DNSServerSearchOrder -join ", " } else { "N/A" }
                }
                $info.NetworkInterfaces += $interface
            }
        }
        
        # 获取当前登录用户（高效方法）
        Write-DebugInfo "获取当前登录用户信息"
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $info.CurrentUser = $currentUser
        
        # 获取本地管理员组成员（高效方法）
        Write-DebugInfo "获取本地管理员组成员"
        try {
            $adminGroup = Get-LocalGroup -Name "Administrators" -ErrorAction SilentlyContinue
            if ($adminGroup) {
                $adminMembers = Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
                    @{
                        Name = $_.Name
                        ObjectClass = $_.ObjectClass
                        PrincipalSource = $_.PrincipalSource
                        ADsPath = "Local"
                    }
                }
                $info.AdminMembers = $adminMembers
                Write-DebugInfo "成功获取到 $($adminMembers.Count) 个本地管理员组成员"
            } else {
                # 备选方法，使用ADSI（与远程查询保持一致）
                Write-DebugInfo "Get-LocalGroup失败，使用ADSI备选方法"
                $adminGroup = [ADSI]"WinNT://./Administrators,group"
                $members = @()
                
                foreach ($member in $adminGroup.Members()) {
                    try {
                        $memberType = $member.GetType().InvokeMember("Class", 'GetProperty', $null, $member, $null)
                        $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                        $memberPath = $member.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $member, $null)
                        
                        # 解析PrincipalSource
                        $principalSource = "Local"
                        if ($memberPath -notlike "*WinNT://./*") {
                            $match = [regex]::Match($memberPath, 'WinNT://([^/]+)/')
                            if ($match.Success) {
                                $sourceName = $match.Groups[1].Value
                                if ($sourceName -ne ".") {
                                    $principalSource = "Domain ($sourceName)"
                                }
                            }
                        }
                        
                        $members += @{
                            Name = $memberName
                            ObjectClass = $memberType
                            PrincipalSource = $principalSource
                            ADsPath = $memberPath
                        }
                        
                        Write-DebugInfo "找到本地管理员组成员: $memberName ($memberType, $principalSource)"
                    }
                    catch {
                        Write-DebugInfo "解析本地管理员组成员失败: $($_.Exception.Message)"
                    }
                }
                
                $info.AdminMembers = $members
                Write-DebugInfo "使用ADSI成功获取到 $($members.Count) 个本地管理员组成员"
            }
        }
        catch {
            Write-ErrorInfo "获取本地管理员组成员失败: $($_.Exception.Message)"
            $info.AdminMembers = @(@{ Name = "查询失败: $($_.Exception.Message)"; ObjectClass = "Error"; PrincipalSource = "N/A" })
        }
        
        Write-DebugInfo "本地计算机信息获取完成"
        return $info
    }
    catch {
        Write-ErrorInfo "获取本地计算机信息时出错: $($_.Exception.Message)"
        throw
    }
}

# 获取远程计算机信息（使用WMI和ADSI）
function Get-RemoteComputerInfo {
    param([string]$TargetIP)
    
    Write-DebugInfo "开始获取远程计算机 $TargetIP 的信息"
    $info = @{}
    
    try {
        # 创建CIM会话选项
        $sessionOption = New-CimSessionOption -Protocol Dcom
        Write-DebugInfo "创建DCOM CIM会话"
        
        # 创建CIM会话
        $cimSession = New-CimSession -ComputerName $TargetIP -SessionOption $sessionOption -ErrorAction Stop
        Write-DebugInfo "成功连接到远程计算机 $TargetIP"
        
        # 获取计算机基本信息
        Write-DebugInfo "获取远程计算机基本信息"
        $computerSystem = Get-CimInstance -CimSession $cimSession -ClassName Win32_ComputerSystem
        $info.ComputerName = $computerSystem.Name
        $info.Domain = $computerSystem.Domain
        $info.FQDN = "$($computerSystem.Name).$($computerSystem.Domain)"
        
        # 获取网络配置信息
        Write-DebugInfo "获取远程计算机网络配置信息"
        $networkConfigs = Get-CimInstance -CimSession $cimSession -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        $info.NetworkInterfaces = @()
        
        foreach ($config in $networkConfigs) {
            if ($config.IPAddress) {
                $interface = @{
                    Description = $config.Description
                    IPAddress = $config.IPAddress[0]
                    MACAddress = $config.MACAddress
                    DefaultGateway = if ($config.DefaultIPGateway) { $config.DefaultIPGateway[0] } else { "N/A" }
                    DNSServers = if ($config.DNSServerSearchOrder) { $config.DNSServerSearchOrder -join ", " } else { "N/A" }
                }
                $info.NetworkInterfaces += $interface
            }
        }
        
        # 获取当前登录用户（使用超高效的WMI方法）
        Write-DebugInfo "获取远程计算机当前登录用户"
        try {
            # 使用优化的高效方法查询当前登录用户
            $users = @()
            $logonIdMap = @{}
            $validLogonTypes = @(2, 10)
            
            Write-DebugInfo "获取交互式和远程桌面登录会话"
            # 获取交互式（2）和远程桌面（10）登录的会话，使用PacketPrivacy认证提高兼容性
            $logonSessions = Get-WmiObject -Class Win32_LogonSession -ComputerName $TargetIP `
                -Authentication PacketPrivacy | 
                Where-Object { $validLogonTypes -contains $_.LogonType }
            
            Write-DebugInfo "找到 $($logonSessions.Count) 个相关登录会话"
            
            # 创建LogonId哈希表以提高查找性能
            foreach ($session in $logonSessions) {
                $logonIdMap[$session.LogonId] = $true
            }
            
            Write-DebugInfo "预加载用户-登录会话关联信息"
            # 预加载用户信息（User-LogonSession关联）
            $loggedOnUsers = Get-WmiObject -Class Win32_LoggedOnUser -ComputerName $TargetIP `
                -Authentication PacketPrivacy
            
            Write-DebugInfo "开始解析登录用户信息"
            foreach ($assoc in $loggedOnUsers) {
                # 使用正则表达式直接提取LogonId，提高性能
                if ($assoc.Dependent -match 'LogonId="(\d+)"') {
                    $logonId = $matches[1]
                    
                    # 使用哈希表快速检查LogonId是否有效
                    if ($logonIdMap.ContainsKey($logonId)) {
                        try {
                            $userObj = [WMI]$assoc.Antecedent
                            $fullName = "$($userObj.Domain)\$($userObj.Name)"
                            
                            # 排除系统虚拟账户和重复用户
                            if ($fullName -notmatch '^(DWM-|UMFD-)' -and $users -notcontains $fullName) {
                                $users += $fullName
                                Write-DebugInfo "找到登录用户: $fullName"
                            }
                        } catch {
                            Write-DebugInfo "忽略解析失败用户: $($_.Exception.Message)"
                        }
                    }
                }
            }
            
            if ($users.Count -gt 0) {
                $info.CurrentUser = $users -join ", "
                Write-DebugInfo "成功获取到 $($users.Count) 个当前登录用户"
            } else {
                $info.CurrentUser = "无当前登录用户"
                Write-DebugInfo "未找到当前登录用户"
            }
        }
        catch {
            Write-DebugInfo "使用优化WMI方法查询登录用户失败: $($_.Exception.Message)"
            $info.CurrentUser = "查询失败: $($_.Exception.Message)"
        }
        
        # 获取本地管理员组成员（使用高效的ADSI方法）
        Write-DebugInfo "获取远程计算机本地管理员组成员"
        try {
            # 使用经过验证的高效ADSI方法直接查询远程计算机的管理员组
            Write-DebugInfo "使用ADSI直接连接到远程计算机管理员组"
            $adminGroup = [ADSI]"WinNT://$TargetIP/Administrators,group"
            
            $members = @()
            foreach ($member in $adminGroup.Members()) {
                try {
                    $memberType = $member.GetType().InvokeMember("Class", 'GetProperty', $null, $member, $null)
                    $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                    $memberPath = $member.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $member, $null)
                    
                    # 解析PrincipalSource
                    $principalSource = "Unknown"
                    if ($memberPath -like "*WinNT://*/") {
                        if ($memberPath -like "*WinNT://$TargetIP/*") {
                            $principalSource = "Local"
                        } else {
                            # 提取域或计算机名
                            $match = [regex]::Match($memberPath, 'WinNT://([^/]+)/')
                            if ($match.Success) {
                                $sourceName = $match.Groups[1].Value
                                if ($sourceName -ne $TargetIP) {
                                    $principalSource = "Domain ($sourceName)"
                                } else {
                                    $principalSource = "Local"
                                }
                            }
                        }
                    }
                    
                    $members += @{
                        Name = $memberName
                        ObjectClass = $memberType
                        PrincipalSource = $principalSource
                        ADsPath = $memberPath
                    }
                    
                    Write-DebugInfo "找到管理员组成员: $memberName ($memberType, $principalSource)"
                }
                catch {
                    Write-DebugInfo "解析管理员组成员失败: $($_.Exception.Message)"
                }
            }
            
            if ($members.Count -gt 0) {
                $info.AdminMembers = $members
                Write-DebugInfo "成功获取到 $($members.Count) 个管理员组成员"
            } else {
                Write-DebugInfo "未找到管理员组成员"
                $info.AdminMembers = @(@{ Name = "未找到管理员组成员"; ObjectClass = "Info"; PrincipalSource = "N/A" })
            }
        }
        catch [System.UnauthorizedAccessException] {
            Write-DebugInfo "ADSI访问被拒绝，尝试WMI备选方法"
            try {
                # 备选方法：使用WMI查询
                $adminMembers = Get-CimInstance -CimSession $cimSession -ClassName Win32_GroupUser | 
                    Where-Object { $_.GroupComponent -match "Administrators" } |
                    ForEach-Object {
                        $member = $_.PartComponent
                        if ($member -match 'Name="([^"]+)"') {
                            @{
                                Name = $matches[1]
                                ObjectClass = "User"
                                PrincipalSource = "Local"
                                ADsPath = "WMI"
                            }
                        }
                    }
                
                if ($adminMembers) {
                    $info.AdminMembers = $adminMembers
                    Write-DebugInfo "使用WMI备选方法成功获取管理员组成员"
                } else {
                    $info.AdminMembers = @(@{ Name = "WMI查询无结果"; ObjectClass = "Error"; PrincipalSource = "N/A" })
                }
            }
            catch {
                Write-ErrorInfo "WMI备选方法也失败: $($_.Exception.Message)"
                $info.AdminMembers = @(@{ Name = "查询失败: 访问被拒绝"; ObjectClass = "Error"; PrincipalSource = "N/A" })
            }
        }
        catch {
            Write-ErrorInfo "获取管理员组成员失败: $($_.Exception.Message)"
            $info.AdminMembers = @(@{ Name = "查询失败: $($_.Exception.Message)"; ObjectClass = "Error"; PrincipalSource = "N/A" })
        }
        
        # 清理CIM会话
        Remove-CimSession -CimSession $cimSession
        Write-DebugInfo "远程计算机信息获取完成"
        
        return $info
    }
    catch {
        Write-ErrorInfo "获取远程计算机信息时出错: $($_.Exception.Message)"
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
        }
        throw
    }
}

# 格式化输出信息
function Format-ComputerInfo {
    param($ComputerInfo)
    
    Write-DebugInfo "格式化计算机信息"
    
    $output = @"
======================================
Windows 计算机信息查询结果
查询时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
======================================

计算机信息:
  计算机名: $($ComputerInfo.ComputerName)
  域名: $($ComputerInfo.Domain)
  FQDN: $($ComputerInfo.FQDN)

当前登录用户:
  $($ComputerInfo.CurrentUser)

网络接口信息:
"@

    foreach ($interface in $ComputerInfo.NetworkInterfaces) {
        $output += @"

  接口: $($interface.Description)
    IP地址: $($interface.IPAddress)
    MAC地址: $($interface.MACAddress)
    默认网关: $($interface.DefaultGateway)
    DNS服务器: $($interface.DNSServers)
"@
    }

    $output += @"


本地管理员组成员:
"@

    if ($ComputerInfo.AdminMembers) {
        foreach ($member in $ComputerInfo.AdminMembers) {
            if ($member.Name) {
                $memberType = if ($member.ObjectClass) { $member.ObjectClass } elseif ($member.Class) { $member.Class } else { "Unknown" }
                $memberSource = if ($member.PrincipalSource) { $member.PrincipalSource } else { "Unknown" }
                $output += "`n  - $($member.Name) [$memberType] ($memberSource)"
            }
        }
    } else {
        $output += "`n  - 无法获取管理员组成员信息"
    }

    $output += @"


======================================
查询完成 - 信息已复制到剪切板
======================================
"@

    return $output
}

# 复制到剪切板
function Copy-ToClipboard {
    param([string]$Text)
    
    Write-DebugInfo "复制信息到剪切板"
    try {
        $Text | Set-Clipboard
        Write-SuccessInfo "信息已成功复制到剪切板"
    }
    catch {
        Write-ErrorInfo "复制到剪切板失败: $($_.Exception.Message)"
        Write-Host "您可以手动复制以下信息:" -ForegroundColor Yellow
        Write-Host $Text
    }
}

# 主函数
function Main {
    Write-SuccessInfo "开始执行Windows计算机信息查询脚本"
    
    try {
        if ([string]::IsNullOrEmpty($IPAddress)) {
            # 查询本地计算机
            Write-SuccessInfo "查询本地计算机信息"
            $computerInfo = Get-LocalComputerInfo
        } else {
            # 检查是否为本地IP
            if (Test-IsLocalIP -IP $IPAddress) {
                Write-SuccessInfo "检测到本地IP地址，使用本地查询方法"
                $computerInfo = Get-LocalComputerInfo
            } else {
                Write-SuccessInfo "查询远程计算机信息: $IPAddress"
                $computerInfo = Get-RemoteComputerInfo -TargetIP $IPAddress
            }
        }
        
        # 格式化并输出信息
        $formattedOutput = Format-ComputerInfo -ComputerInfo $computerInfo
        Write-Host $formattedOutput
        
        # 复制到剪切板
        Copy-ToClipboard -Text $formattedOutput
        
        Write-SuccessInfo "脚本执行完成"
    }
    catch {
        Write-ErrorInfo "脚本执行失败: $($_.Exception.Message)"
        if ($OutputDebug) {
            Write-Host "详细错误信息:" -ForegroundColor Red
            Write-Host $_.Exception.StackTrace -ForegroundColor Red
        }
        exit 1
    }
}

# 执行主函数
Main
