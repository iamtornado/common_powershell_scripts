<#
.SYNOPSIS
    批量修改远程Windows计算机DNS设置并加入域（增强并行处理版本）

.DESCRIPTION
    此脚本用于批量对远程Windows计算机执行以下操作：
    1. 修改DNS服务器地址
    2. 加入指定的Active Directory域
    3. 验证域加入是否成功
    4. 自动重启计算机（可选）
    
    脚本包含预检查功能，避免重复操作已经配置正确的计算机。
    支持高性能并行处理，具备超时控制、断点续传、进度条显示等企业级特性。

.PARAMETER ComputerListFile
    包含目标计算机名称列表的文本文件路径（绝对路径）

.PARAMETER DomainName
    要加入的域名

.PARAMETER DomainController
    域控制器服务器名称

.PARAMETER PrimaryDNS
    主DNS服务器地址

.PARAMETER SecondaryDNS
    辅助DNS服务器地址（可选）

.PARAMETER NetworkInterfaceIndex
    网络接口索引号（默认为自动检测活动接口）

.PARAMETER LogFile
    日志文件路径（可选）

.PARAMETER SkipRestart
    跳过自动重启（可选开关）

.PARAMETER MaxConcurrency
    最大并行处理数量（默认为10，建议范围5-30）

.PARAMETER BatchSize
    批处理大小，分批处理大量计算机（默认为50）

.PARAMETER TimeoutMinutes
    单个计算机处理超时时间（分钟，默认10分钟）

.PARAMETER MaxRetries
    失败重试次数（默认2次）

.PARAMETER ResumeFile
    断点续传状态文件路径（可选）

.PARAMETER ShowProgressBar
    显示图形进度条（可选开关）

.PARAMETER LocalAdminUsername
    远程Windows计算机本地管理员用户名（默认为administrator）

.PARAMETER DomainAdminUsername
    域管理员用户名（默认为joindomain）

.EXAMPLE
    .\Join-DomainRemoteBatch-Parallel-Enhanced.ps1 -ComputerListFile "C:\servers.txt" -DomainName "contoso.com" -DomainController "DC01.contoso.com" -PrimaryDNS "192.168.1.10" -MaxConcurrency 10

.EXAMPLE
    # 高并发处理大量计算机，带超时和重试
    .\Join-DomainRemoteBatch-Parallel-Enhanced.ps1 -ComputerListFile "C:\1000servers.txt" -DomainName "contoso.com" -DomainController "DC01.contoso.com" -PrimaryDNS "192.168.1.10" -SecondaryDNS "192.168.1.11" -MaxConcurrency 20 -BatchSize 100 -TimeoutMinutes 15 -MaxRetries 3 -ShowProgressBar

.EXAMPLE
    # 断点续传模式
    .\Join-DomainRemoteBatch-Parallel-Enhanced.ps1 -ComputerListFile "C:\servers.txt" -DomainName "contoso.com" -DomainController "DC01.contoso.com" -PrimaryDNS "192.168.1.10" -ResumeFile "C:\progress.json"

.EXAMPLE
    # 使用自定义用户名
    .\Join-DomainRemoteBatch-Parallel-Enhanced.ps1 -ComputerListFile "C:\servers.txt" -DomainName "contoso.com" -DomainController "DC01.contoso.com" -PrimaryDNS "192.168.1.10" -LocalAdminUsername "localadmin" -DomainAdminUsername "domainadmin"

.NOTES
    作者: tornadoami
    版本: 2.3 (增强并行处理版 - 分离域加入和重启)
    创建日期: 2025年9月3日
    微信公众号：AI发烧友
    DreamAI官网：https://alidocs.dingtalk.com/i/nodes/Amq4vjg890AlRbA6Td9ZvlpDJ3kdP0wQ?utm_scene=team_space
    github：https://github.com/iamtornado/common_powershell_scripts
    
    要求:
    - PowerShell 5.1 或更高版本
    - 目标计算机必须可通过WinRM访问
    - 需要域管理员凭据和本地管理员凭据
    
    增强特性:
    - 支持1-30台计算机同时处理
    - 智能超时控制和作业清理
    - 失败自动重试机制
    - 断点续传功能
    - 图形进度条显示
    - 内存优化和资源管理
    - 详细性能分析

.LINK
    https://github.com/iamtornado/common_powershell_scripts
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "包含计算机名称的文本文件路径")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ComputerListFile,
    
    [Parameter(Mandatory = $true, HelpMessage = "要加入的域名")]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName,
    
    [Parameter(Mandatory = $true, HelpMessage = "域控制器服务器名称")]
    [ValidateNotNullOrEmpty()]
    [string]$DomainController,
    
    [Parameter(Mandatory = $true, HelpMessage = "主DNS服务器地址")]
    [ValidateScript({[System.Net.IPAddress]::TryParse($_, [ref]$null)})]
    [string]$PrimaryDNS,
    
    [Parameter(Mandatory = $false, HelpMessage = "辅助DNS服务器地址")]
    [ValidateScript({[System.Net.IPAddress]::TryParse($_, [ref]$null)})]
    [string]$SecondaryDNS,
    
    [Parameter(Mandatory = $false, HelpMessage = "网络接口索引号")]
    [int]$NetworkInterfaceIndex = 0,
    
    [Parameter(Mandatory = $false, HelpMessage = "日志文件路径")]
    [string]$LogFile = ".\Join-Domain-Enhanced-$(Get-Date -Format 'yyyyMMdd-HHmmss').log",
    
    [Parameter(Mandatory = $false, HelpMessage = "跳过自动重启")]
    [switch]$SkipRestart,
    
    [Parameter(Mandatory = $false, HelpMessage = "最大并行处理数量")]
    [ValidateRange(1, 30)]
    [int]$MaxConcurrency = 10,
    
    [Parameter(Mandatory = $false, HelpMessage = "批处理大小")]
    [ValidateRange(10, 1000)]
    [int]$BatchSize = 50,
    
    [Parameter(Mandatory = $false, HelpMessage = "单个计算机处理超时时间（分钟）")]
    [ValidateRange(5, 60)]
    [int]$TimeoutMinutes = 10,
    
    [Parameter(Mandatory = $false, HelpMessage = "失败重试次数")]
    [ValidateRange(0, 5)]
    [int]$MaxRetries = 2,
    
    [Parameter(Mandatory = $false, HelpMessage = "断点续传状态文件路径")]
    [string]$ResumeFile,
    
    [Parameter(Mandatory = $false, HelpMessage = "显示图形进度条")]
    [switch]$ShowProgressBar,
    
    [Parameter(Mandatory = $false, HelpMessage = "本地管理员用户名")]
    [ValidateNotNullOrEmpty()]
    [string]$LocalAdminUsername = "administrator",
    
    [Parameter(Mandatory = $false, HelpMessage = "域管理员用户名")]
    [ValidateNotNullOrEmpty()]
    [string]$DomainAdminUsername = "joindomain"
)

# 设置错误处理
$ErrorActionPreference = "Stop"

# 创建线程安全的日志对象和统计对象
$script:LogLock = [System.Object]::new()
$script:StatsLock = [System.Object]::new()
$script:Stats = @{
    TotalComputers = 0
    ProcessedCount = 0
    SuccessCount = 0
    FailureCount = 0
    SkippedCount = 0
    RetryCount = 0
}

# 增强的线程安全日志记录函数
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "PROGRESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    $logEntry = "[$timestamp] [TID:$threadId] [$Level] $Message"
    
    # 线程安全的日志写入
    [System.Threading.Monitor]::Enter($script:LogLock)
    try {
        # 输出到控制台（DEBUG级别不输出到控制台）
        if ($Level -ne "DEBUG") {
            switch ($Level) {
                "ERROR" { Write-Host $logEntry -ForegroundColor Red }
                "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
                "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
                "PROGRESS" { Write-Host $logEntry -ForegroundColor Cyan }
                default { Write-Host $logEntry -ForegroundColor White }
            }
        }
        
        # 写入日志文件
        try {
            Add-Content -Path $LogFile -Value $logEntry -ErrorAction Stop
        }
        catch {
            Write-Warning "无法写入日志文件: $($_.Exception.Message)"
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:LogLock)
    }
}

# 线程安全的统计更新函数
function Update-Stats {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Processed", "Success", "Failure", "Skipped", "Retry")]
        [string]$Type
    )
    
    [System.Threading.Monitor]::Enter($script:StatsLock)
    try {
        switch ($Type) {
            "Processed" { $script:Stats.ProcessedCount++ }
            "Success" { $script:Stats.SuccessCount++ }
            "Failure" { $script:Stats.FailureCount++ }
            "Skipped" { $script:Stats.SkippedCount++ }
            "Retry" { $script:Stats.RetryCount++ }
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:StatsLock)
    }
}

# 进度条更新函数
function Update-ProgressBar {
    param(
        [int]$CurrentCount,
        [int]$TotalCount,
        [string]$Status = "处理中..."
    )
    
    if ($ShowProgressBar.IsPresent -and $TotalCount -gt 0) {
        $percentComplete = [math]::Round(($CurrentCount / $TotalCount) * 100, 1)
        Write-Progress -Activity "批量域加入操作" -Status "$Status ($CurrentCount/$TotalCount)" -PercentComplete $percentComplete
    }
}

# 保存进度状态函数
function Save-ProgressState {
    param(
        [array]$AllResults,
        [array]$RemainingComputers
    )
    
    if (-not [string]::IsNullOrEmpty($ResumeFile)) {
        try {
            $progressState = @{
                Timestamp = Get-Date
                CompletedComputers = $AllResults | Where-Object { $_.Status -in @("操作成功", "已正确配置", "操作失败", "连通性失败", "状态检查失败") }
                RemainingComputers = $RemainingComputers
                Statistics = $script:Stats.Clone()
            }
            $progressState | ConvertTo-Json -Depth 10 | Set-Content -Path $ResumeFile -Encoding UTF8
            Write-Log "进度状态已保存到: $ResumeFile" -Level "DEBUG"
        }
        catch {
            Write-Log "无法保存进度状态: $($_.Exception.Message)" -Level "WARNING"
        }
    }
}

# 加载进度状态函数
function Load-ProgressState {
    if (-not [string]::IsNullOrEmpty($ResumeFile) -and (Test-Path $ResumeFile)) {
        try {
            $progressState = Get-Content -Path $ResumeFile -Encoding UTF8 | ConvertFrom-Json
            Write-Log "从断点续传文件加载进度状态: $ResumeFile" -Level "INFO"
            return $progressState
        }
        catch {
            Write-Log "无法加载进度状态文件: $($_.Exception.Message)" -Level "WARNING"
            return $null
        }
    }
    return $null
}

# 清理超时作业函数
function Clear-TimeoutJobs {
    param(
        [array]$Jobs,
        [int]$TimeoutSeconds
    )
    
    $timeoutJobs = @()
    $currentTime = Get-Date
    
    foreach ($jobInfo in $Jobs) {
        $elapsedTime = ($currentTime - $jobInfo.StartTime).TotalSeconds
        if ($elapsedTime -gt $TimeoutSeconds -and $jobInfo.Job.State -eq 'Running') {
            Write-Log "作业超时，强制停止: $($jobInfo.ComputerName) (耗时: $([math]::Round($elapsedTime, 1))秒)" -Level "WARNING"
            
            try {
                Stop-Job -Job $jobInfo.Job -ErrorAction Stop
                Remove-Job -Job $jobInfo.Job -Force -ErrorAction Stop
                $timeoutJobs += $jobInfo
            }
            catch {
                Write-Log "清理超时作业失败: $($jobInfo.ComputerName) - $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    
    return $timeoutJobs
}

# 增强的并行处理脚本块
$ProcessComputerScriptBlock = {
    param(
        $ComputerName,
        $DomainName, 
        $DomainController,
        $PrimaryDNS,
        $SecondaryDNS,
        $NetworkInterfaceIndex,
        $SkipRestart,
        $LocalCredential,
        $DomainCredential,
        $LogFile,
        $MaxRetries
    )
    
    # 作业内部函数定义
    function Write-JobLog {
        param($Message, $Level = "INFO")
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $jobId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        $logEntry = "[$timestamp] [JOB:$jobId] [$Level] $Message"
        
        # 直接写入文件（避免并发冲突）
        try {
            $logEntry | Add-Content -Path $LogFile -ErrorAction SilentlyContinue
        } catch {
            # 忽略日志写入错误
        }
        
        # 返回日志用于主线程显示
        return @{
            Message = $logEntry
            Level = $Level
        }
    }
    
    # 带重试的连通性测试
    function Test-JobRemoteComputerWithRetry {
        param($ComputerName, $Credential, $MaxRetries)
        
        for ($retry = 0; $retry -le $MaxRetries; $retry++) {
            try {
                # 测试WinRM连通性
                $sessionOption = New-PSSessionOption -OpenTimeout 30000 -CancelTimeout 15000
                $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ErrorAction Stop
                Remove-PSSession $session
                
                return @{ Success = $true; Error = $null; Retries = $retry }
            }
            catch {
                if ($retry -eq $MaxRetries) {
                    return @{ Success = $false; Error = $_.Exception.Message; Retries = $retry }
                }
                Start-Sleep -Seconds (2 * ($retry + 1))  # 递增延迟
            }
        }
    }
    
    # 获取远程计算机状态（带超时）
    function Get-JobRemoteComputerStatus {
        param($ComputerName, $Credential, $ExpectedDomain, $ExpectedPrimaryDNS, $ExpectedSecondaryDNS)
        
        try {
            $sessionOption = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 60000
            $result = Invoke-Command -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ScriptBlock {
                param($ExpectedDomain, $ExpectedPrimaryDNS, $ExpectedSecondaryDNS)
                
                try {
                    # 检查域成员身份 - 兼容 Windows Server 2012 R2
                    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                    $isDomainMember = $computerSystem.Domain -eq $ExpectedDomain
                    
                    # 获取活动网络接口 - 兼容 Windows Server 2012 R2
                    try {
                        # 尝试使用 Get-NetAdapter (Windows 8/Server 2012+)
                        $activeInterface = Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.Virtual -eq $false} | Select-Object -First 1
                    } catch {
                        # 如果失败，使用 WMI 方法
                        $networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object {$_.NetConnectionStatus -eq 2 -and $_.AdapterTypeId -eq 0}
                        if ($networkAdapters) {
                            $activeInterface = @{
                                InterfaceIndex = $networkAdapters[0].InterfaceIndex
                                Name = $networkAdapters[0].Name
                            }
                        } else {
                            $activeInterface = $null
                        }
                    }
                    
                    if (-not $activeInterface) {
                        return @{
                            IsDomainMember = $isDomainMember
                            CurrentDomain = $computerSystem.Domain
                            DNSConfigured = $false
                            InterfaceIndex = $null
                            CurrentDNS = @()
                            Error = "未找到活动的网络接口"
                        }
                    }
                    
                    # 检查DNS配置 - 兼容 Windows Server 2012 R2
                    try {
                        # 尝试使用 Get-DnsClientServerAddress (Windows 8/Server 2012+)
                        $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $activeInterface.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
                        $currentDNS = $dnsServers.ServerAddresses
                    } catch {
                        # 如果失败，使用 WMI 方法获取DNS服务器
                        $networkConfig = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $activeInterface.InterfaceIndex -and $_.IPEnabled -eq $true}
                        if ($networkConfig -and $networkConfig.DNSServerSearchOrder) {
                            $currentDNS = $networkConfig.DNSServerSearchOrder
                        } else {
                            $currentDNS = @()
                        }
                    }
                    
                    $dnsConfigured = $false
                    if ($currentDNS.Count -gt 0) {
                        $dnsConfigured = ($currentDNS[0] -eq $ExpectedPrimaryDNS)
                        if ($ExpectedSecondaryDNS -and $currentDNS.Count -gt 1) {
                            $dnsConfigured = $dnsConfigured -and ($currentDNS[1] -eq $ExpectedSecondaryDNS)
                        }
                    }
                    
                    return @{
                        IsDomainMember = $isDomainMember
                        CurrentDomain = $computerSystem.Domain
                        DNSConfigured = $dnsConfigured
                        InterfaceIndex = $activeInterface.InterfaceIndex
                        CurrentDNS = $currentDNS
                        Error = $null
                    }
                }
                catch {
                    return @{
                        IsDomainMember = $false
                        CurrentDomain = "UNKNOWN"
                        DNSConfigured = $false
                        InterfaceIndex = $null
                        CurrentDNS = @()
                        Error = "状态检查异常: $($_.Exception.Message)"
                    }
                }
            } -ArgumentList $ExpectedDomain, $ExpectedPrimaryDNS, $ExpectedSecondaryDNS
            
            return $result
        }
        catch {
            return @{
                IsDomainMember = $false
                CurrentDomain = "UNKNOWN"
                DNSConfigured = $false
                InterfaceIndex = $null
                CurrentDNS = @()
                Error = "远程连接失败: $($_.Exception.Message)"
            }
        }
    }
    
    # 执行域加入操作（带重试）
    function Join-JobRemoteComputerToDomain {
        param($ComputerName, $LocalCredential, $DomainCredential, $DomainName, $DomainController, $PrimaryDNS, $SecondaryDNS, $InterfaceIndex, $SkipRestart, $MaxRetries)
        
        for ($retry = 0; $retry -le $MaxRetries; $retry++) {
            try {
                # 构建DNS服务器数组
                $dnsServers = @($PrimaryDNS)
                if ($SecondaryDNS) {
                    $dnsServers += $SecondaryDNS
                }
                
                $sessionOption = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 300000  # 5分钟超时
                $result = Invoke-Command -ComputerName $ComputerName -Credential $LocalCredential -SessionOption $sessionOption -ScriptBlock {
                    param($DnsServers, $InterfaceIndex, $DomainCredential, $DomainName, $DomainController, $SkipRestart)
                    
                    try {
                        # 设置DNS服务器地址 - 兼容 Windows Server 2012 R2
                        try {
                            # 尝试使用 Set-DnsClientServerAddress (Windows 8/Server 2012+)
                            Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses $DnsServers -ErrorAction Stop
                        } catch {
                            # 如果失败，使用 WMI 方法设置DNS
                            $networkConfig = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $InterfaceIndex -and $_.IPEnabled -eq $true}
                            if ($networkConfig) {
                                $networkConfig.SetDNSServerSearchOrder($DnsServers) | Out-Null
                            }
                        }
                        
                        # 验证DNS设置
                        Start-Sleep -Seconds 3
                        try {
                            $dnsResult = Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
                            $currentDNS = $dnsResult
                        } catch {
                            # 使用 WMI 方法验证DNS设置
                            $networkConfig = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $InterfaceIndex -and $_.IPEnabled -eq $true}
                            if ($networkConfig -and $networkConfig.DNSServerSearchOrder) {
                                $currentDNS = @{ ServerAddresses = $networkConfig.DNSServerSearchOrder }
                            } else {
                                $currentDNS = @{ ServerAddresses = @() }
                            }
                        }
                        
                        # 测试DNS解析
                        try {
                            $null = Resolve-DnsName -Name $DomainName -ErrorAction Stop
                        } catch {
                            # DNS解析失败但继续
                        }
                        
                        # 清理DNS缓存
                        Clear-DnsClientCache -ErrorAction SilentlyContinue
                        
                        # 加入域（不立即重启）
                        $joinResult = Add-Computer -DomainCredential $DomainCredential -DomainName $DomainName -Server $DomainController -PassThru -ErrorAction Stop
                        
                        # 验证域加入是否成功
                        Start-Sleep -Seconds 5  # 等待域加入操作完成
                        
                        # 重新检查域成员身份以确认加入成功
                        $verifyResult = $null
                        try {
                            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                            $isNowDomainMember = $computerSystem.PartOfDomain -and ($computerSystem.Domain -eq $DomainName)
                            $verifyResult = @{
                                Success = $isNowDomainMember
                                CurrentDomain = $computerSystem.Domain
                                PartOfDomain = $computerSystem.PartOfDomain
                            }
                        } catch {
                            # 如果CIM失败，尝试WMI方法
                            try {
                                $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
                                $isNowDomainMember = $computerSystem.PartOfDomain -and ($computerSystem.Domain -eq $DomainName)
                                $verifyResult = @{
                                    Success = $isNowDomainMember
                                    CurrentDomain = $computerSystem.Domain
                                    PartOfDomain = $computerSystem.PartOfDomain
                                }
                            } catch {
                                $verifyResult = @{
                                    Success = $false
                                    Error = "无法验证域加入状态: $($_.Exception.Message)"
                                }
                            }
                        }
                        
                        if (-not $verifyResult.Success) {
                            if ($verifyResult.Error) {
                                throw "域加入验证失败: $($verifyResult.Error)"
                            } else {
                                throw "域加入验证失败: 计算机未成功加入域 '$DomainName'，当前域: '$($verifyResult.CurrentDomain)'"
                            }
                        }
                        
                        # 如果不跳过重启，则执行重启
                        if (-not $SkipRestart) {
                            Restart-Computer -Force -ErrorAction Stop
                        }
                        
                        # 构建成功消息
                        $successMessage = "域加入操作成功完成，已验证加入域 '$DomainName'"
                        if (-not $SkipRestart) {
                            $successMessage += "，计算机正在重启"
                        } else {
                            $successMessage += "，需要手动重启以完成配置"
                        }
                        
                        return @{
                            Success = $true
                            Result = $joinResult
                            Message = $successMessage
                            DNSServers = $currentDNS.ServerAddresses
                            VerificationResult = $verifyResult
                        }
                    }
                    catch {
                        return @{
                            Success = $false
                            Result = $null
                            Message = "域加入操作失败: $($_.Exception.Message)"
                            DNSServers = @()
                        }
                    }
                } -ArgumentList $dnsServers, $InterfaceIndex, $DomainCredential, $DomainName, $DomainController, $SkipRestart
                
                if ($result.Success) {
                    return @{
                        Success = $true
                        Result = $result.Result
                        Message = $result.Message
                        Retries = $retry
                        DNSServers = $result.DNSServers
                    }
                } else {
                    if ($retry -eq $MaxRetries) {
                        return @{
                            Success = $false
                            Result = $null
                            Message = $result.Message
                            Retries = $retry
                            DNSServers = @()
                        }
                    }
                    Start-Sleep -Seconds (5 * ($retry + 1))  # 递增延迟
                }
            }
            catch {
                if ($retry -eq $MaxRetries) {
                    return @{
                        Success = $false
                        Result = $null
                        Message = "域加入操作异常: $($_.Exception.Message)"
                        Retries = $retry
                        DNSServers = @()
                    }
                }
                Start-Sleep -Seconds (5 * ($retry + 1))  # 递增延迟
            }
        }
    }
    
    # 主处理逻辑
    $result = @{
        ComputerName = $ComputerName
        Status = "处理中"
        Action = ""
        StartTime = Get-Date
        EndTime = $null
        Logs = @()
        Retries = 0
        DNSServers = @()
    }
    
    try {
        $result.Logs += Write-JobLog "开始处理计算机: $ComputerName" "INFO"
        
        # 验证连通性（带重试）
        $connectTest = Test-JobRemoteComputerWithRetry -ComputerName $ComputerName -Credential $LocalCredential -MaxRetries $MaxRetries
        $result.Retries += $connectTest.Retries
        
        if (-not $connectTest.Success) {
            $result.Status = "连通性失败"
            $result.Action = "跳过"
            $result.Logs += Write-JobLog "计算机 $ComputerName 连通性验证失败 (重试${($connectTest.Retries)}次): $($connectTest.Error)" "ERROR"
            return $result
        }
        
        if ($connectTest.Retries -gt 0) {
            $result.Logs += Write-JobLog "计算机 $ComputerName 连通性验证成功 (重试${($connectTest.Retries)}次)" "SUCCESS"
        } else {
            $result.Logs += Write-JobLog "计算机 $ComputerName 连通性验证成功" "SUCCESS"
        }
        
        # 检查当前状态
        $status = Get-JobRemoteComputerStatus -ComputerName $ComputerName -Credential $LocalCredential -ExpectedDomain $DomainName -ExpectedPrimaryDNS $PrimaryDNS -ExpectedSecondaryDNS $SecondaryDNS
        
        if ($status.Error) {
            $result.Status = "状态检查错误"
            $result.Action = "跳过"
            $result.Logs += Write-JobLog "计算机 $ComputerName 状态检查错误: $($status.Error)" "ERROR"
            return $result
        }
        
        # 检查是否需要操作
        $needsDNSUpdate = -not $status.DNSConfigured
        $needsDomainJoin = -not $status.IsDomainMember
        
        $result.Logs += Write-JobLog "计算机 $ComputerName 状态检查:" "INFO"
        $result.Logs += Write-JobLog "  当前域: $($status.CurrentDomain)" "INFO"
        $result.Logs += Write-JobLog "  域成员身份: $($status.IsDomainMember)" "INFO"
        $result.Logs += Write-JobLog "  DNS配置状态: $($status.DNSConfigured)" "INFO"
        $result.Logs += Write-JobLog "  当前DNS服务器: $($status.CurrentDNS -join ', ')" "INFO"
        $result.DNSServers = $status.CurrentDNS
        
        if (-not $needsDNSUpdate -and -not $needsDomainJoin) {
            $result.Status = "已正确配置"
            $result.Action = "跳过"
            if ($status.IsDomainMember) {
                $result.Logs += Write-JobLog "✅ 计算机 $ComputerName 已经是域 '$($status.CurrentDomain)' 的成员，DNS配置正确，跳过操作" "SUCCESS"
            } else {
                $result.Logs += Write-JobLog "✅ 计算机 $ComputerName 配置已正确，跳过操作" "SUCCESS"
            }
            return $result
        }
        
        # 详细说明需要执行的操作
        if ($needsDomainJoin -and $needsDNSUpdate) {
            $result.Logs += Write-JobLog "⚠️ 计算机 $ComputerName 需要配置DNS并加入域 '$DomainName'" "WARNING"
        } elseif ($needsDomainJoin) {
            $result.Logs += Write-JobLog "⚠️ 计算机 $ComputerName 需要加入域 '$DomainName'" "WARNING"
        } elseif ($needsDNSUpdate) {
            $result.Logs += Write-JobLog "⚠️ 计算机 $ComputerName 需要更新DNS配置" "WARNING"
        }
        
        # 确定网络接口索引
        $interfaceIndex = $NetworkInterfaceIndex
        if ($interfaceIndex -eq 0) {
            $interfaceIndex = $status.InterfaceIndex
        }
        
        if ($null -eq $interfaceIndex) {
            $result.Status = "网络接口错误"
            $result.Action = "跳过"
            $result.Logs += Write-JobLog "计算机 $ComputerName 无法确定网络接口索引" "ERROR"
            return $result
        }
        
        # 执行域加入操作（带重试）
        $result.Logs += Write-JobLog "开始对计算机 $ComputerName 执行域加入操作" "INFO"
        $joinResult = Join-JobRemoteComputerToDomain -ComputerName $ComputerName -LocalCredential $LocalCredential -DomainCredential $DomainCredential -DomainName $DomainName -DomainController $DomainController -PrimaryDNS $PrimaryDNS -SecondaryDNS $SecondaryDNS -InterfaceIndex $interfaceIndex -SkipRestart $SkipRestart -MaxRetries $MaxRetries
        
        $result.Retries += $joinResult.Retries
        $result.DNSServers = $joinResult.DNSServers
        
        if ($joinResult.Success) {
            $result.Status = "操作成功"
            $result.Action = if ($SkipRestart) { "已配置（需手动重启）" } else { "已配置并重启" }
            if ($joinResult.Retries -gt 0) {
                $result.Logs += Write-JobLog "计算机 $ComputerName 域加入操作成功 (重试${($joinResult.Retries)}次)" "SUCCESS"
            } else {
                $result.Logs += Write-JobLog "计算机 $ComputerName 域加入操作成功" "SUCCESS"
            }
        } else {
            $result.Status = "操作失败"
            $result.Action = "请检查日志"
            $result.Logs += Write-JobLog "计算机 $ComputerName 域加入操作失败 (重试${($joinResult.Retries)}次): $($joinResult.Message)" "ERROR"
        }
    }
    catch {
        $result.Status = "处理异常"
        $result.Action = "异常终止"
        $result.Logs += Write-JobLog "计算机 $ComputerName 处理异常: $($_.Exception.Message)" "ERROR"
    }
    finally {
        $result.EndTime = Get-Date
        $duration = ($result.EndTime - $result.StartTime).TotalSeconds
        $result.Logs += Write-JobLog "计算机 $ComputerName 处理完成，耗时: $([math]::Round($duration, 2))秒，重试: $($result.Retries)次" "INFO"
    }
    
    return $result
}

#region 主程序
# ================================================================================
# 增强并行处理主程序
# ================================================================================

Write-Log "=== 批量域加入脚本开始执行（增强并行处理版本） ===" -Level "INFO"
# 获取日志文件的绝对路径
$absoluteLogPath = (Resolve-Path $LogFile -ErrorAction SilentlyContinue).Path
if (-not $absoluteLogPath) {
    # 如果文件还不存在，构建绝对路径
    $absoluteLogPath = Join-Path (Get-Location).Path (Split-Path $LogFile -Leaf)
}
Write-Log "📄 日志文件: $absoluteLogPath" -Level "INFO"
Write-Log "参数配置:" -Level "INFO"
Write-Log "  计算机列表文件: $ComputerListFile" -Level "INFO"
Write-Log "  目标域: $DomainName" -Level "INFO"
Write-Log "  域控制器: $DomainController" -Level "INFO"
Write-Log "  主DNS: $PrimaryDNS" -Level "INFO"
if ($SecondaryDNS) { Write-Log "  辅助DNS: $SecondaryDNS" -Level "INFO" }
Write-Log "  最大并行数: $MaxConcurrency" -Level "INFO"
Write-Log "  批处理大小: $BatchSize" -Level "INFO"
Write-Log "  超时时间: $TimeoutMinutes 分钟" -Level "INFO"
Write-Log "  最大重试: $MaxRetries 次" -Level "INFO"
Write-Log "  日志文件: $LogFile" -Level "INFO"
Write-Log "  跳过重启: $SkipRestart" -Level "INFO"
Write-Log "  本地管理员用户名: $LocalAdminUsername" -Level "INFO"
Write-Log "  域管理员用户名: $DomainAdminUsername" -Level "INFO"
if ($ResumeFile) { Write-Log "  断点续传: $ResumeFile" -Level "INFO" }
if ($ShowProgressBar) { Write-Log "  显示进度条: 是" -Level "INFO" }

try {
    # 检查是否需要断点续传
    $resumeState = Load-ProgressState
    $allResults = @()
    $computers = @()
    
    if ($resumeState) {
        Write-Log "检测到断点续传文件，继续上次的处理..." -Level "INFO"
        $allResults = $resumeState.CompletedComputers
        $computers = $resumeState.RemainingComputers
        
        # 恢复统计信息
        $script:Stats = $resumeState.Statistics
        
        Write-Log "已完成: $($allResults.Count) 台，剩余: $($computers.Count) 台" -Level "INFO"
    } else {
        # 读取计算机列表
        Write-Log "读取计算机列表文件..." -Level "INFO"
        $computers = Get-Content $ComputerListFile | Where-Object { $_.Trim() -ne "" -and -not $_.Trim().StartsWith("#") }
        Write-Log "共发现 $($computers.Count) 台计算机" -Level "INFO"
    }
    
    if ($computers.Count -eq 0) {
        if ($resumeState -and $allResults.Count -gt 0) {
            Write-Log "所有计算机已处理完成！" -Level "SUCCESS"
        } else {
            throw "计算机列表为空"
        }
        return
    }
    
    # 初始化统计信息
    $script:Stats.TotalComputers = ($allResults.Count + $computers.Count)
    $script:Stats.ProcessedCount = $allResults.Count
    
    # 获取凭据（使用指定的用户名）
    Write-Log "请提供本地管理员凭据（用户名: $LocalAdminUsername）..." -Level "INFO"
    $localCredential = Get-Credential -UserName $LocalAdminUsername -Message "请输入本地管理员凭据"
    
    Write-Log "请提供域管理员凭据（用户名: $DomainName\$DomainAdminUsername）..." -Level "INFO"
    $domainUserName = "$DomainName\$DomainAdminUsername"
    $domainCredential = Get-Credential -UserName $domainUserName -Message "请输入域管理员凭据"
    
    # 计算超时秒数
    $timeoutSeconds = $TimeoutMinutes * 60
    
    # 分批处理
    $batches = @()
    for ($i = 0; $i -lt $computers.Count; $i += $BatchSize) {
        $end = [Math]::Min($i + $BatchSize - 1, $computers.Count - 1)
        $batches += ,@($computers[$i..$end])
    }
    
    Write-Log "将分 $($batches.Count) 批处理，每批最多 $BatchSize 台计算机" -Level "INFO"
    
    # 初始化进度条
    Update-ProgressBar -CurrentCount $script:Stats.ProcessedCount -TotalCount $script:Stats.TotalComputers -Status "初始化中..."
    
    # 处理每批计算机
    for ($batchIndex = 0; $batchIndex -lt $batches.Count; $batchIndex++) {
        $currentBatch = $batches[$batchIndex]
        Write-Log "=== 开始处理第 $($batchIndex + 1) 批，共 $($currentBatch.Count) 台计算机 ===" -Level "PROGRESS"
        
        # 创建并行作业
        $jobs = @()
        $batchStartTime = Get-Date
        
        foreach ($computer in $currentBatch) {
            $computer = $computer.Trim()
            if ([string]::IsNullOrEmpty($computer)) { continue }
            
            # 启动并行作业
            $job = Start-Job -ScriptBlock $ProcessComputerScriptBlock -ArgumentList @(
                $computer,
                $DomainName,
                $DomainController, 
                $PrimaryDNS,
                $SecondaryDNS,
                $NetworkInterfaceIndex,
                $SkipRestart.IsPresent,
                $localCredential,
                $domainCredential,
                $LogFile,
                $MaxRetries
            )
            
            $jobs += @{
                Job = $job
                ComputerName = $computer
                StartTime = Get-Date
            }
            
            # 控制并发数量
            while ($jobs.Count -ge $MaxConcurrency) {
                Start-Sleep -Milliseconds 500  # 减少轮询间隔
                
                # 清理超时作业
                $timeoutJobs = Clear-TimeoutJobs -Jobs $jobs -TimeoutSeconds $timeoutSeconds
                foreach ($timeoutJob in $timeoutJobs) {
                    # 创建超时结果
                    $timeoutResult = @{
                        ComputerName = $timeoutJob.ComputerName
                        Status = "处理超时"
                        Action = "超时终止"
                        StartTime = $timeoutJob.StartTime
                        EndTime = Get-Date
                        Logs = @(@{
                            Message = "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'))] [JOB] [ERROR] 计算机 $($timeoutJob.ComputerName) 处理超时"
                            Level = "ERROR"
                        })
                        Retries = 0
                        DNSServers = @()
                    }
                    
                    $allResults += $timeoutResult
                    Update-Stats -Type "Processed"
                    Update-Stats -Type "Failure"
                    
                    # 从作业列表中移除
                    $jobs = $jobs | Where-Object { $_.Job.Id -ne $timeoutJob.Job.Id }
                    
                    # 更新进度
                    Update-ProgressBar -CurrentCount $script:Stats.ProcessedCount -TotalCount $script:Stats.TotalComputers -Status "处理超时: $($timeoutJob.ComputerName)"
                    Write-Log "进度: $($script:Stats.ProcessedCount)/$($script:Stats.TotalComputers) - $($timeoutJob.ComputerName): 处理超时" -Level "PROGRESS"
                }
                
                # 处理完成的作业
                $completedJobs = $jobs | Where-Object { $_.Job.State -eq 'Completed' }
                foreach ($completedJob in $completedJobs) {
                    $result = Receive-Job -Job $completedJob.Job
                    Remove-Job -Job $completedJob.Job
                    
                    # 更新统计
                    Update-Stats -Type "Processed"
                    if ($result.Retries -gt 0) { Update-Stats -Type "Retry" }
                    
                    switch ($result.Status) {
                        "操作成功" { Update-Stats -Type "Success" }
                        "已正确配置" { Update-Stats -Type "Skipped" }
                        default { Update-Stats -Type "Failure" }
                    }
                    
                    # 显示结果日志
                    foreach ($log in $result.Logs) {
                        if ($log.Level -ne "DEBUG") {  # 过滤DEBUG日志
                            Write-Host $log.Message -ForegroundColor $(
                                switch ($log.Level) {
                                    "ERROR" { "Red" }
                                    "SUCCESS" { "Green" }
                                    "WARNING" { "Yellow" }
                                    default { "White" }
                                }
                            )
                        }
                    }
                    
                    $allResults += $result
                    
                    # 更新进度条和显示进度
                    $progress = [math]::Round(($script:Stats.ProcessedCount / $script:Stats.TotalComputers) * 100, 1)
                    Update-ProgressBar -CurrentCount $script:Stats.ProcessedCount -TotalCount $script:Stats.TotalComputers -Status "$($result.ComputerName): $($result.Status)"
                    
                    $statusColor = switch ($result.Status) {
                        "操作成功" { "SUCCESS" }
                        "已正确配置" { "SUCCESS" }
                        default { "ERROR" }
                    }
                    
                    # 为已正确配置的计算机显示特殊提示
                    if ($result.Status -eq "已正确配置") {
                        Write-Log "进度: $($script:Stats.ProcessedCount)/$($script:Stats.TotalComputers) ($progress%) - ✅ $($result.ComputerName): 已是域成员，无需处理" -Level $statusColor
                    } else {
                        Write-Log "进度: $($script:Stats.ProcessedCount)/$($script:Stats.TotalComputers) ($progress%) - $($result.ComputerName): $($result.Status)" -Level $statusColor
                    }
                    
                    # 从作业列表中移除
                    $jobs = $jobs | Where-Object { $_.Job.Id -ne $completedJob.Job.Id }
                }
                
                # 定期保存进度
                if ($script:Stats.ProcessedCount % 10 -eq 0) {
                    Save-ProgressState -AllResults $allResults -RemainingComputers ($computers | Select-Object -Skip $script:Stats.ProcessedCount)
                }
            }
        }
        
        # 等待当前批次所有作业完成
        Write-Log "等待第 $($batchIndex + 1) 批作业完成..." -Level "INFO"
        while ($jobs.Count -gt 0) {
            Start-Sleep -Milliseconds 500
            
            # 清理超时作业
            $timeoutJobs = Clear-TimeoutJobs -Jobs $jobs -TimeoutSeconds $timeoutSeconds
            foreach ($timeoutJob in $timeoutJobs) {
                # 处理超时作业（同上）
                $timeoutResult = @{
                    ComputerName = $timeoutJob.ComputerName
                    Status = "处理超时"
                    Action = "超时终止"
                    StartTime = $timeoutJob.StartTime
                    EndTime = Get-Date
                    Logs = @(@{
                        Message = "[$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'))] [JOB] [ERROR] 计算机 $($timeoutJob.ComputerName) 处理超时"
                        Level = "ERROR"
                    })
                    Retries = 0
                    DNSServers = @()
                }
                
                $allResults += $timeoutResult
                Update-Stats -Type "Processed"
                Update-Stats -Type "Failure"
                
                $jobs = $jobs | Where-Object { $_.Job.Id -ne $timeoutJob.Job.Id }
                
                Update-ProgressBar -CurrentCount $script:Stats.ProcessedCount -TotalCount $script:Stats.TotalComputers -Status "处理超时: $($timeoutJob.ComputerName)"
                Write-Log "进度: $($script:Stats.ProcessedCount)/$($script:Stats.TotalComputers) - $($timeoutJob.ComputerName): 处理超时" -Level "ERROR"
            }
            
            # 处理完成的作业
            $completedJobs = $jobs | Where-Object { $_.Job.State -eq 'Completed' }
            foreach ($completedJob in $completedJobs) {
                $result = Receive-Job -Job $completedJob.Job
                Remove-Job -Job $completedJob.Job
                
                # 更新统计
                Update-Stats -Type "Processed"
                if ($result.Retries -gt 0) { Update-Stats -Type "Retry" }
                
                switch ($result.Status) {
                    "操作成功" { Update-Stats -Type "Success" }
                    "已正确配置" { Update-Stats -Type "Skipped" }
                    default { Update-Stats -Type "Failure" }
                }
                
                # 显示结果日志
                foreach ($log in $result.Logs) {
                    if ($log.Level -ne "DEBUG") {
                        Write-Host $log.Message -ForegroundColor $(
                            switch ($log.Level) {
                                "ERROR" { "Red" }
                                "SUCCESS" { "Green" }
                                "WARNING" { "Yellow" }
                                default { "White" }
                            }
                        )
                    }
                }
                
                $allResults += $result
                
                # 更新进度
                $progress = [math]::Round(($script:Stats.ProcessedCount / $script:Stats.TotalComputers) * 100, 1)
                Update-ProgressBar -CurrentCount $script:Stats.ProcessedCount -TotalCount $script:Stats.TotalComputers -Status "$($result.ComputerName): $($result.Status)"
                
                $statusColor = switch ($result.Status) {
                    "操作成功" { "SUCCESS" }
                    "已正确配置" { "SUCCESS" }
                    default { "ERROR" }
                }
                
                # 为已正确配置的计算机显示特殊提示
                if ($result.Status -eq "已正确配置") {
                    Write-Log "进度: $($script:Stats.ProcessedCount)/$($script:Stats.TotalComputers) ($progress%) - ✅ $($result.ComputerName): 已是域成员，无需处理" -Level $statusColor
                } else {
                    Write-Log "进度: $($script:Stats.ProcessedCount)/$($script:Stats.TotalComputers) ($progress%) - $($result.ComputerName): $($result.Status)" -Level $statusColor
                }
                
                $jobs = $jobs | Where-Object { $_.Job.Id -ne $completedJob.Job.Id }
            }
        }
        
        $batchDuration = ((Get-Date) - $batchStartTime).TotalMinutes
        Write-Log "第 $($batchIndex + 1) 批处理完成，耗时: $([math]::Round($batchDuration, 1)) 分钟" -Level "SUCCESS"
        
        # 批次间延迟和垃圾回收
        if ($batchIndex -lt $batches.Count - 1) {
            Write-Log "批次间休息 5 秒，清理内存..." -Level "INFO"
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            Start-Sleep -Seconds 5
        }
        
        # 保存进度状态
        Save-ProgressState -AllResults $allResults -RemainingComputers ($computers | Select-Object -Skip $script:Stats.ProcessedCount)
    }
    
    # 完成进度条
    if ($ShowProgressBar.IsPresent) {
        Write-Progress -Activity "批量域加入操作" -Completed
    }
    
    # 输出最终汇总报告
    Write-Log "=== 增强并行处理完成汇总 ===" -Level "INFO"
    Write-Log "总计算机数: $($script:Stats.TotalComputers)" -Level "INFO"
    Write-Log "成功处理: $($script:Stats.SuccessCount)" -Level "SUCCESS"
    Write-Log "处理失败: $($script:Stats.FailureCount)" -Level "ERROR"
    Write-Log "已是域成员: $($script:Stats.SkippedCount)" -Level "SUCCESS"
    Write-Log "总重试次数: $($script:Stats.RetryCount)" -Level "INFO"
    
    # 特别提示已加入域的计算机
    if ($script:Stats.SkippedCount -gt 0) {
        Write-Log " " -Level "INFO"
        Write-Log "🎯 重要提示: 发现 $($script:Stats.SkippedCount) 台计算机已经是域成员，无需重复加域操作！" -Level "SUCCESS"
        Write-Log "   这些计算机已正确配置，为您节省了大量时间和资源。" -Level "SUCCESS"
    }
    
    # 性能统计
    $validResults = $allResults | Where-Object { $_.EndTime -and $_.StartTime }
    if ($validResults.Count -gt 0) {
        $avgProcessingTime = ($validResults | ForEach-Object { ($_.EndTime - $_.StartTime).TotalSeconds } | Measure-Object -Average).Average
        $maxProcessingTime = ($validResults | ForEach-Object { ($_.EndTime - $_.StartTime).TotalSeconds } | Measure-Object -Maximum).Maximum
        $minProcessingTime = ($validResults | ForEach-Object { ($_.EndTime - $_.StartTime).TotalSeconds } | Measure-Object -Minimum).Minimum
        
        Write-Log "平均处理时间: $([math]::Round($avgProcessingTime, 2)) 秒/台" -Level "INFO"
        Write-Log "最快处理时间: $([math]::Round($minProcessingTime, 2)) 秒" -Level "INFO"
        Write-Log "最慢处理时间: $([math]::Round($maxProcessingTime, 2)) 秒" -Level "INFO"
        
        # 重试统计
        $retriedResults = $validResults | Where-Object { $_.Retries -gt 0 }
        if ($retriedResults.Count -gt 0) {
            $avgRetries = ($retriedResults | ForEach-Object { $_.Retries } | Measure-Object -Average).Average
            Write-Log "需要重试的计算机: $($retriedResults.Count) 台" -Level "INFO"
            Write-Log "平均重试次数: $([math]::Round($avgRetries, 1)) 次" -Level "INFO"
        }
    }
    
    # 分类显示详细结果
    Write-Log "详细结果:" -Level "INFO"
    
    # 已正确配置的计算机（突出显示）
    $alreadyConfigured = $allResults | Where-Object { $_.Status -eq "已正确配置" }
    if ($alreadyConfigured.Count -gt 0) {
        Write-Log " " -Level "INFO"
        Write-Log "✅ 已正确配置的计算机 ($($alreadyConfigured.Count) 台):" -Level "SUCCESS"
        foreach ($result in $alreadyConfigured) {
            $duration = if ($result.EndTime -and $result.StartTime) { 
                [math]::Round(($result.EndTime - $result.StartTime).TotalSeconds, 1) 
            } else { 
                "N/A" 
            }
            $dnsInfo = if ($result.DNSServers -and $result.DNSServers.Count -gt 0) { " [当前DNS:$($result.DNSServers -join ',')]" } else { "" }
            Write-Log "  ✅ $($result.ComputerName): 已是域成员，无需处理 (检查耗时:${duration}s)${dnsInfo}" -Level "SUCCESS"
        }
    }
    
    # 操作成功的计算机
    $successful = $allResults | Where-Object { $_.Status -eq "操作成功" }
    if ($successful.Count -gt 0) {
        Write-Log " " -Level "INFO"
        Write-Log "🎉 操作成功的计算机 ($($successful.Count) 台):" -Level "SUCCESS"
        foreach ($result in $successful) {
            $duration = if ($result.EndTime -and $result.StartTime) { 
                [math]::Round(($result.EndTime - $result.StartTime).TotalSeconds, 1) 
            } else { 
                "N/A" 
            }
            $retryInfo = if ($result.Retries -gt 0) { " (重试:$($result.Retries))" } else { "" }
            $dnsInfo = if ($result.DNSServers -and $result.DNSServers.Count -gt 0) { " [DNS:$($result.DNSServers -join ',')]" } else { "" }
            Write-Log "  🎉 $($result.ComputerName): $($result.Action) (耗时:${duration}s)${retryInfo}${dnsInfo}" -Level "SUCCESS"
        }
    }
    
    # 失败的计算机
    $failed = $allResults | Where-Object { $_.Status -notin @("已正确配置", "操作成功") }
    if ($failed.Count -gt 0) {
        Write-Log " " -Level "INFO"
        Write-Log "❌ 处理失败的计算机 ($($failed.Count) 台):" -Level "ERROR"
        foreach ($result in $failed) {
            $duration = if ($result.EndTime -and $result.StartTime) { 
                [math]::Round(($result.EndTime - $result.StartTime).TotalSeconds, 1) 
            } else { 
                "N/A" 
            }
            $retryInfo = if ($result.Retries -gt 0) { " (重试:$($result.Retries))" } else { "" }
            Write-Log "  ❌ $($result.ComputerName): $($result.Status) - $($result.Action) (耗时:${duration}s)${retryInfo}" -Level "ERROR"
        }
    }
    
    # 清理断点续传文件
    if ($ResumeFile -and (Test-Path $ResumeFile)) {
        try {
            Remove-Item $ResumeFile -Force
            Write-Log "已清理断点续传文件: $ResumeFile" -Level "INFO"
        } catch {
            Write-Log "无法清理断点续传文件: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    Write-Log "=== 增强并行处理脚本执行完成 ===" -Level "SUCCESS"
    Write-Log " " -Level "INFO"
    # 获取日志文件的绝对路径用于最终显示
    $finalLogPath = (Resolve-Path $LogFile -ErrorAction SilentlyContinue).Path
    if (-not $finalLogPath) {
        $finalLogPath = Join-Path (Get-Location).Path (Split-Path $LogFile -Leaf)
    }
    Write-Log "📄 详细日志文件路径: $finalLogPath" -Level "INFO"
    Write-Log "   您可以查看此文件获取完整的执行详情和错误信息" -Level "INFO"
}
catch {
    Write-Log "脚本执行发生致命错误: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "错误详情: $($_.Exception.StackTrace)" -Level "ERROR"
    Write-Log " " -Level "INFO"
    # 获取日志文件的绝对路径用于错误显示
    $errorLogPath = (Resolve-Path $LogFile -ErrorAction SilentlyContinue).Path
    if (-not $errorLogPath) {
        $errorLogPath = Join-Path (Get-Location).Path (Split-Path $LogFile -Leaf)
    }
    Write-Log "📄 详细日志文件路径: $errorLogPath" -Level "ERROR"
    Write-Log "   请查看此文件获取完整的错误信息和执行详情" -Level "ERROR"
    
    # 保存错误状态
    if ($allResults) {
        Save-ProgressState -AllResults $allResults -RemainingComputers ($computers | Select-Object -Skip $script:Stats.ProcessedCount)
    }
    
    exit 1
}
finally {
    # 清理资源
    Write-Log "清理系统资源..." -Level "DEBUG"
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    
    # 完成进度条
    if ($ShowProgressBar.IsPresent) {
        Write-Progress -Activity "批量域加入操作" -Completed
    }
}

#endregion
