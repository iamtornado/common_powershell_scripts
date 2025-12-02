#Requires -Version 5.1

<#
.SYNOPSIS
    批量查询远程Windows主机的计算机名、IP地址和MAC地址

.DESCRIPTION
    此脚本通过WinRM批量查询远程Windows主机的系统信息，包括：
    - 计算机名
    - IP地址（第一个活动网卡的IPv4地址）
    - MAC地址（第一个活动网卡的物理地址）
    
    支持并行处理、完善的错误处理和详细的日志记录，结果导出为CSV文件。

.PARAMETER ComputerListFile
    包含目标计算机名称列表的文本文件路径（每行一个计算机名）

.PARAMETER Credential
    用于连接远程计算机的凭据。如果不提供，则使用当前用户凭据。

.PARAMETER OutputCSV
    输出CSV文件路径。如果不指定，将使用默认路径（带时间戳）。

.PARAMETER LogFile
    日志文件路径。如果不指定，将使用默认路径（带时间戳）。

.PARAMETER MaxConcurrency
    最大并行处理数量（默认100，建议范围1-200）

.PARAMETER TimeoutSeconds
    单个主机查询超时时间（秒，默认30秒）

.PARAMETER MaxRetries
    失败重试次数（默认2次）

.EXAMPLE
    .\Get-RemoteHostInfo.ps1 -ComputerListFile "C:\computers.txt"
    使用当前用户凭据查询计算机列表中的主机信息

.EXAMPLE
    .\Get-RemoteHostInfo.ps1 -ComputerListFile "C:\computers.txt" -Credential (Get-Credential) -MaxConcurrency 150
    使用指定凭据，并行处理20台主机

.EXAMPLE
    .\Get-RemoteHostInfo.ps1 -ComputerListFile "C:\computers.txt" -OutputCSV "C:\results.csv" -LogFile "C:\query.log"
    指定输出文件和日志文件路径

.NOTES
    作者: tornadoami
    版本: 1.0
    创建日期: 2025-12-01
    微信公众号：AI发烧友
    DreamAI官网：https://alidocs.dingtalk.com/i/nodes/Amq4vjg890AlRbA6Td9ZvlpDJ3kdP0wQ?utm_scene=team_space
    github：https://github.com/iamtornado/common_powershell_scripts
    
    要求:
    - PowerShell 5.1 或更高版本
    - 目标计算机必须可通过WinRM访问
    - 需要适当的权限（本地管理员或域管理员）
    
    前置条件:
    - 确保WinRM服务在目标计算机上已启用并配置
    - 确保防火墙规则允许WinRM连接（HTTP 5985, HTTPS 5986）

.LINK
    https://github.com/iamtornado/common_powershell_scripts
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "包含计算机名称的文本文件路径")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) {
            return $true
        }
        throw "文件不存在: $_"
    })]
    [string]$ComputerListFile,
    
    [Parameter(Mandatory = $false, HelpMessage = "用于连接远程计算机的凭据")]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory = $false, HelpMessage = "输出CSV文件路径")]
    [string]$OutputCSV,
    
    [Parameter(Mandatory = $false, HelpMessage = "日志文件路径")]
    [string]$LogFile,
    
    [Parameter(Mandatory = $false, HelpMessage = "最大并行处理数量")]
    [ValidateRange(1, 200)]
    [int]$MaxConcurrency = 100,
    
    [Parameter(Mandatory = $false, HelpMessage = "单个主机查询超时时间（秒）")]
    [ValidateRange(5, 300)]
    [int]$TimeoutSeconds = 30,
    
    [Parameter(Mandatory = $false, HelpMessage = "失败重试次数")]
    [ValidateRange(0, 5)]
    [int]$MaxRetries = 2
)

# 设置错误处理
$ErrorActionPreference = "Continue"

# 脚本开始时间
$ScriptStartTime = Get-Date

# 设置默认输出文件路径
if ([string]::IsNullOrWhiteSpace($OutputCSV)) {
    $OutputCSV = ".\RemoteHostInfo-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
}

# 设置默认日志文件路径
if ([string]::IsNullOrWhiteSpace($LogFile)) {
    $LogFile = ".\Get-RemoteHostInfo-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
}

# 创建线程安全的日志对象和统计对象
$script:LogLock = [System.Object]::new()
$script:StatsLock = [System.Object]::new()
$script:Stats = @{
    TotalComputers = 0
    ProcessedCount = 0
    SuccessCount = 0
    FailureCount = 0
    RetryCount = 0
}

# 结果集合
$script:Results = [System.Collections.ArrayList]::new()

# ============================================================================
# 函数：线程安全的日志记录
# ============================================================================
function Write-Log {
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Message = "",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "PROGRESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    # 如果消息为空，只写入空行到日志文件，不输出到控制台
    if ([string]::IsNullOrWhiteSpace($Message)) {
        [System.Threading.Monitor]::Enter($script:LogLock)
        try {
            Add-Content -Path $LogFile -Value "" -ErrorAction SilentlyContinue
        }
        finally {
            [System.Threading.Monitor]::Exit($script:LogLock)
        }
        return
    }
    
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

# ============================================================================
# 函数：线程安全的统计更新
# ============================================================================
function Update-Stats {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Processed", "Success", "Failure", "Retry")]
        [string]$Type
    )
    
    [System.Threading.Monitor]::Enter($script:StatsLock)
    try {
        switch ($Type) {
            "Processed" { $script:Stats.ProcessedCount++ }
            "Success" { $script:Stats.SuccessCount++ }
            "Failure" { $script:Stats.FailureCount++ }
            "Retry" { $script:Stats.RetryCount++ }
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:StatsLock)
    }
}

# ============================================================================
# 函数：格式化MAC地址
# ============================================================================
function Format-MACAddress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MACAddress
    )
    
    if ([string]::IsNullOrWhiteSpace($MACAddress)) {
        return ""
    }
    
    # 移除所有分隔符
    $mac = $MACAddress -replace '[:\-\s]', ''
    
    # 验证MAC地址格式（12个十六进制字符）
    if ($mac -match '^[0-9A-Fa-f]{12}$') {
        # 格式化为标准格式：AA-BB-CC-DD-EE-FF
        return ($mac -split '(..)' | Where-Object { $_ }) -join '-'
    }
    
    return $MACAddress
}

# ============================================================================
# 函数：测试WinRM连通性
# ============================================================================
function Test-RemoteHostConnectivity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 2,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 30
    )
    
    for ($retry = 0; $retry -le $MaxRetries; $retry++) {
        try {
            # 测试WinRM连通性
            $sessionOption = New-PSSessionOption -OpenTimeout ($TimeoutSeconds * 1000) -CancelTimeout ($TimeoutSeconds * 500)
            
            if ($Credential) {
                $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ErrorAction Stop
            }
            else {
                $session = New-PSSession -ComputerName $ComputerName -SessionOption $sessionOption -ErrorAction Stop
            }
            
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

# ============================================================================
# 函数：查询远程主机信息（在远程主机上执行）
# ============================================================================
function Get-RemoteHostInfoScriptBlock {
    # 此函数返回要在远程主机上执行的脚本块
    return {
        try {
            $result = @{
                ComputerName = $null
                IPAddress = $null
                MACAddress = $null
                Error = $null
            }
            
            # 获取计算机名
            try {
                $result.ComputerName = $env:COMPUTERNAME
                if ([string]::IsNullOrWhiteSpace($result.ComputerName)) {
                    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                    $result.ComputerName = $computerSystem.Name
                }
            }
            catch {
                $result.Error = "获取计算机名失败: $($_.Exception.Message)"
                return $result
            }
            
            # 获取网络适配器信息
            try {
                # 优先使用 Get-NetAdapter (Windows 8/Server 2012+)
                $activeAdapter = $null
                try {
                    $activeAdapter = Get-NetAdapter | Where-Object {
                        $_.Status -eq "Up" -and 
                        $_.Virtual -eq $false -and
                        $_.Name -notlike "*Loopback*" -and
                        $_.Name -notlike "*Teredo*" -and
                        $_.Name -notlike "*isatap*"
                    } | Select-Object -First 1
                }
                catch {
                    # 如果Get-NetAdapter不可用，使用WMI方法
                    Write-Verbose "Get-NetAdapter不可用，使用WMI方法"
                }
                
                if ($activeAdapter) {
                    # 使用Get-NetAdapter获取的信息
                    $interfaceIndex = $activeAdapter.InterfaceIndex
                    
                    # 获取IP地址
                    $ipConfig = Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                               Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -ne "0.0.0.0" } | 
                               Select-Object -First 1
                    
                    if ($ipConfig) {
                        $result.IPAddress = $ipConfig.IPAddress
                        $result.MACAddress = $activeAdapter.MacAddress
                    }
                    else {
                        # 如果没有找到IPv4地址，尝试使用WMI
                        throw "未找到有效的IPv4地址"
                    }
                }
                else {
                    # 使用WMI方法（兼容Windows Server 2012 R2）
                    $networkConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | 
                                     Where-Object { 
                                         $_.IPEnabled -eq $true -and 
                                         $_.IPAddress -and 
                                         $_.MACAddress -and
                                         $_.IPAddress[0] -ne "127.0.0.1" -and
                                         $_.IPAddress[0] -ne "0.0.0.0"
                                     } | 
                                     Select-Object -First 1
                    
                    if ($networkConfigs) {
                        $result.IPAddress = $networkConfigs.IPAddress[0]
                        $result.MACAddress = $networkConfigs.MACAddress
                    }
                    else {
                        throw "未找到活动的网络适配器"
                    }
                }
            }
            catch {
                $result.Error = "获取网络信息失败: $($_.Exception.Message)"
                return $result
            }
            
            return $result
        }
        catch {
            return @{
                ComputerName = $null
                IPAddress = $null
                MACAddress = $null
                Error = "执行失败: $($_.Exception.Message)"
            }
        }
    }
}

# ============================================================================
# 函数：查询单个远程主机信息
# ============================================================================
function Get-RemoteHostInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 2
    )
    
    $queryStartTime = Get-Date
    
    try {
        # 测试连通性
        Write-Log "正在测试 $ComputerName 的WinRM连通性..." -Level "DEBUG"
        $connectivity = Test-RemoteHostConnectivity -ComputerName $ComputerName -Credential $Credential -MaxRetries $MaxRetries -TimeoutSeconds $TimeoutSeconds
        
        if (-not $connectivity.Success) {
            $errorMsg = "WinRM连接失败: $($connectivity.Error)"
            Write-Log "$ComputerName - $errorMsg" -Level "ERROR"
            return @{
                ComputerName = $ComputerName
                IPAddress = ""
                MACAddress = ""
                Status = "失败"
                ErrorMessage = $errorMsg
                QueryTime = (Get-Date) - $queryStartTime
            }
        }
        
        # 执行远程查询
        Write-Log "正在查询 $ComputerName 的系统信息..." -Level "DEBUG"
        $sessionOption = New-PSSessionOption -OpenTimeout ($TimeoutSeconds * 1000) -OperationTimeout ($TimeoutSeconds * 1000)
        $scriptBlock = Get-RemoteHostInfoScriptBlock
        
        if ($Credential) {
            $remoteResult = Invoke-Command -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ScriptBlock $scriptBlock -ErrorAction Stop
        }
        else {
            $remoteResult = Invoke-Command -ComputerName $ComputerName -SessionOption $sessionOption -ScriptBlock $scriptBlock -ErrorAction Stop
        }
        
        # 处理查询结果
        if ($remoteResult.Error) {
            $errorMsg = $remoteResult.Error
            Write-Log "$ComputerName - $errorMsg" -Level "ERROR"
            return @{
                ComputerName = if ($remoteResult.ComputerName) { $remoteResult.ComputerName } else { $ComputerName }
                IPAddress = ""
                MACAddress = ""
                Status = "失败"
                ErrorMessage = $errorMsg
                QueryTime = (Get-Date) - $queryStartTime
            }
        }
        
        # 格式化MAC地址
        $formattedMAC = Format-MACAddress -MACAddress $remoteResult.MACAddress
        
        # 成功返回结果
        Write-Log "$ComputerName - 查询成功: IP=$($remoteResult.IPAddress), MAC=$formattedMAC" -Level "SUCCESS"
        return @{
            ComputerName = $remoteResult.ComputerName
            IPAddress = $remoteResult.IPAddress
            MACAddress = $formattedMAC
            Status = "成功"
            ErrorMessage = ""
            QueryTime = (Get-Date) - $queryStartTime
        }
    }
    catch {
        $errorMsg = "查询失败: $($_.Exception.Message)"
        Write-Log "$ComputerName - $errorMsg" -Level "ERROR"
        return @{
            ComputerName = $ComputerName
            IPAddress = ""
            MACAddress = ""
            Status = "失败"
            ErrorMessage = $errorMsg
            QueryTime = (Get-Date) - $queryStartTime
        }
    }
}

# ============================================================================
# 函数：处理单个主机（用于并行处理）
# ============================================================================
function Process-SingleHost {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 2
    )
    
    try {
        $result = Get-RemoteHostInfo -ComputerName $ComputerName -Credential $Credential -TimeoutSeconds $TimeoutSeconds -MaxRetries $MaxRetries
        
        # 更新统计
        Update-Stats -Type "Processed"
        if ($result.Status -eq "成功") {
            Update-Stats -Type "Success"
        }
        else {
            Update-Stats -Type "Failure"
        }
        
        # 添加结果到集合（线程安全）
        [System.Threading.Monitor]::Enter($script:StatsLock)
        try {
            [void]$script:Results.Add($result)
        }
        finally {
            [System.Threading.Monitor]::Exit($script:StatsLock)
        }
        
        # 显示进度
        $processed = $script:Stats.ProcessedCount
        $total = $script:Stats.TotalComputers
        $percent = if ($total -gt 0) { [math]::Round(($processed / $total) * 100, 1) } else { 0 }
        Write-Log "[进度: $processed/$total ($percent%)] $ComputerName - $($result.Status)" -Level "PROGRESS"
        
        return $result
    }
    catch {
        Write-Log "$ComputerName - 处理异常: $($_.Exception.Message)" -Level "ERROR"
        Update-Stats -Type "Processed"
        Update-Stats -Type "Failure"
        
        $errorResult = @{
            ComputerName = $ComputerName
            IPAddress = ""
            MACAddress = ""
            Status = "失败"
            ErrorMessage = "处理异常: $($_.Exception.Message)"
            QueryTime = [TimeSpan]::Zero
        }
        
        [System.Threading.Monitor]::Enter($script:StatsLock)
        try {
            [void]$script:Results.Add($errorResult)
        }
        finally {
            [System.Threading.Monitor]::Exit($script:StatsLock)
        }
        
        return $errorResult
    }
}

# ============================================================================
# 函数：导出结果到CSV
# ============================================================================
function Export-ResultsToCSV {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [array]$Results
    )
    
    try {
        # 准备CSV数据
        $csvData = $Results | ForEach-Object {
            [PSCustomObject]@{
                ComputerName = $_.ComputerName
                IPAddress = $_.IPAddress
                MACAddress = $_.MACAddress
                Status = $_.Status
                ErrorMessage = $_.ErrorMessage
                QueryTimeSeconds = [math]::Round($_.QueryTime.TotalSeconds, 2)
            }
        }
        
        # 导出到CSV
        $csvData | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8BOM -Force
        
        Write-Log "结果已导出到: $OutputPath" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "导出CSV失败: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# ============================================================================
# 主程序开始
# ============================================================================

Write-Log "========================================" -Level "INFO"
Write-Log "远程主机信息查询脚本开始执行" -Level "INFO"
Write-Log "========================================" -Level "INFO"
Write-Log "计算机列表文件: $ComputerListFile" -Level "INFO"
Write-Log "输出CSV文件: $OutputCSV" -Level "INFO"
Write-Log "日志文件: $LogFile" -Level "INFO"
Write-Log "最大并行数: $MaxConcurrency" -Level "INFO"
Write-Log "超时时间: $TimeoutSeconds 秒" -Level "INFO"
Write-Log "最大重试次数: $MaxRetries" -Level "INFO"
Write-Log "" -Level "INFO"

# 读取计算机列表
try {
    Write-Log "正在读取计算机列表..." -Level "INFO"
    $computers = Get-Content -Path $ComputerListFile -ErrorAction Stop | 
                 Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | 
                 ForEach-Object { $_.Trim() } | 
                 Where-Object { $_ -ne "" }
    
    if ($computers.Count -eq 0) {
        Write-Log "错误: 计算机列表文件为空或没有有效的计算机名" -Level "ERROR"
        exit 1
    }
    
    $script:Stats.TotalComputers = $computers.Count
    Write-Log "成功读取 $($computers.Count) 台计算机" -Level "SUCCESS"
}
catch {
    Write-Log "读取计算机列表文件失败: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# 检查PowerShell版本，选择并行处理方式
$psVersion = $PSVersionTable.PSVersion
Write-Log "PowerShell版本: $psVersion" -Level "INFO"

# 并行处理
Write-Log "开始并行查询..." -Level "INFO"

if ($psVersion.Major -ge 7) {
    # PowerShell 7+ 使用 ForEach-Object -Parallel
    Write-Log "使用 PowerShell 7+ 并行处理模式" -Level "INFO"
    
    # 创建ref变量用于在并行脚本块中更新统计
    $statsRef = [ref]$script:Stats
    $resultsRef = [ref]$script:Results
    
    $computers | ForEach-Object -Parallel {
        # 导入必要的变量和函数到并行脚本块
        $Credential = $using:Credential
        $TimeoutSeconds = $using:TimeoutSeconds
        $MaxRetries = $using:MaxRetries
        $LogFile = $using:LogFile
        $StatsRef = $using:statsRef
        $ResultsRef = $using:resultsRef
        $StatsLock = $using:script:StatsLock
        $LogLock = $using:script:LogLock
        
        # 重新定义函数（因为并行脚本块需要独立的函数定义）
        function Write-Log {
            param([AllowEmptyString()][string]$Message = "", [string]$Level = "INFO")
            # 如果消息为空，只写入空行到日志文件，不输出到控制台
            if ([string]::IsNullOrWhiteSpace($Message)) {
                [System.Threading.Monitor]::Enter($LogLock)
                try {
                    Add-Content -Path $LogFile -Value "" -ErrorAction SilentlyContinue
                }
                finally {
                    [System.Threading.Monitor]::Exit($LogLock)
                }
                return
            }
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
            $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
            $logEntry = "[$timestamp] [TID:$threadId] [$Level] $Message"
            [System.Threading.Monitor]::Enter($LogLock)
            try {
                if ($Level -ne "DEBUG") {
                    switch ($Level) {
                        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
                        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
                        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
                        "PROGRESS" { Write-Host $logEntry -ForegroundColor Cyan }
                        default { Write-Host $logEntry -ForegroundColor White }
                    }
                }
                Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
            }
            finally {
                [System.Threading.Monitor]::Exit($LogLock)
            }
        }
        
        function Format-MACAddress {
            param([string]$MACAddress)
            if ([string]::IsNullOrWhiteSpace($MACAddress)) { return "" }
            $mac = $MACAddress -replace '[:\-\s]', ''
            if ($mac -match '^[0-9A-Fa-f]{12}$') {
                return ($mac -split '(..)' | Where-Object { $_ }) -join '-'
            }
            return $MACAddress
        }
        
        function Test-RemoteHostConnectivity {
            param([string]$ComputerName, [object]$Credential, [int]$MaxRetries, [int]$TimeoutSeconds)
            for ($retry = 0; $retry -le $MaxRetries; $retry++) {
                try {
                    $sessionOption = New-PSSessionOption -OpenTimeout ($TimeoutSeconds * 1000) -CancelTimeout ($TimeoutSeconds * 500)
                    if ($Credential) {
                        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ErrorAction Stop
                    } else {
                        $session = New-PSSession -ComputerName $ComputerName -SessionOption $sessionOption -ErrorAction Stop
                    }
                    Remove-PSSession $session
                    return @{ Success = $true; Error = $null; Retries = $retry }
                } catch {
                    if ($retry -eq $MaxRetries) {
                        return @{ Success = $false; Error = $_.Exception.Message; Retries = $retry }
                    }
                    Start-Sleep -Seconds (2 * ($retry + 1))
                }
            }
        }
        
        function Get-RemoteHostInfoScriptBlock {
            return {
                try {
                    $result = @{ ComputerName = $null; IPAddress = $null; MACAddress = $null; Error = $null }
                    $result.ComputerName = $env:COMPUTERNAME
                    if ([string]::IsNullOrWhiteSpace($result.ComputerName)) {
                        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                        $result.ComputerName = $computerSystem.Name
                    }
                    try {
                        $activeAdapter = Get-NetAdapter | Where-Object {
                            $_.Status -eq "Up" -and $_.Virtual -eq $false -and
                            $_.Name -notlike "*Loopback*" -and $_.Name -notlike "*Teredo*" -and $_.Name -notlike "*isatap*"
                        } | Select-Object -First 1
                        if ($activeAdapter) {
                            $ipConfig = Get-NetIPAddress -InterfaceIndex $activeAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                                       Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -ne "0.0.0.0" } | Select-Object -First 1
                            if ($ipConfig) {
                                $result.IPAddress = $ipConfig.IPAddress
                                $result.MACAddress = $activeAdapter.MacAddress
                            } else { throw "未找到有效的IPv4地址" }
                        } else { throw "未找到活动适配器" }
                    } catch {
                        $networkConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | 
                                         Where-Object { 
                                             $_.IPEnabled -eq $true -and $_.IPAddress -and $_.MACAddress -and
                                             $_.IPAddress[0] -ne "127.0.0.1" -and $_.IPAddress[0] -ne "0.0.0.0"
                                         } | Select-Object -First 1
                        if ($networkConfigs) {
                            $result.IPAddress = $networkConfigs.IPAddress[0]
                            $result.MACAddress = $networkConfigs.MACAddress
                        } else { throw "未找到活动的网络适配器" }
                    }
                    return $result
                } catch {
                    return @{ ComputerName = $null; IPAddress = $null; MACAddress = $null; Error = "执行失败: $($_.Exception.Message)" }
                }
            }
        }
        
        function Get-RemoteHostInfo {
            param([string]$ComputerName, [object]$Credential, [int]$TimeoutSeconds, [int]$MaxRetries)
            $queryStartTime = Get-Date
            try {
                $connectivity = Test-RemoteHostConnectivity -ComputerName $ComputerName -Credential $Credential -MaxRetries $MaxRetries -TimeoutSeconds $TimeoutSeconds
                if (-not $connectivity.Success) {
                    return @{
                        ComputerName = $ComputerName
                        IPAddress = ""
                        MACAddress = ""
                        Status = "失败"
                        ErrorMessage = "WinRM连接失败: $($connectivity.Error)"
                        QueryTime = (Get-Date) - $queryStartTime
                    }
                }
                $sessionOption = New-PSSessionOption -OpenTimeout ($TimeoutSeconds * 1000) -OperationTimeout ($TimeoutSeconds * 1000)
                $scriptBlock = Get-RemoteHostInfoScriptBlock
                if ($Credential) {
                    $remoteResult = Invoke-Command -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ScriptBlock $scriptBlock -ErrorAction Stop
                } else {
                    $remoteResult = Invoke-Command -ComputerName $ComputerName -SessionOption $sessionOption -ScriptBlock $scriptBlock -ErrorAction Stop
                }
                if ($remoteResult.Error) {
                    return @{
                        ComputerName = if ($remoteResult.ComputerName) { $remoteResult.ComputerName } else { $ComputerName }
                        IPAddress = ""
                        MACAddress = ""
                        Status = "失败"
                        ErrorMessage = $remoteResult.Error
                        QueryTime = (Get-Date) - $queryStartTime
                    }
                }
                $formattedMAC = Format-MACAddress -MACAddress $remoteResult.MACAddress
                return @{
                    ComputerName = $remoteResult.ComputerName
                    IPAddress = $remoteResult.IPAddress
                    MACAddress = $formattedMAC
                    Status = "成功"
                    ErrorMessage = ""
                    QueryTime = (Get-Date) - $queryStartTime
                }
            } catch {
                return @{
                    ComputerName = $ComputerName
                    IPAddress = ""
                    MACAddress = ""
                    Status = "失败"
                    ErrorMessage = "查询失败: $($_.Exception.Message)"
                    QueryTime = (Get-Date) - $queryStartTime
                }
            }
        }
        
        # 定义Update-Stats函数（在并行脚本块中）
        function Update-Stats {
            param([string]$Type)
            [System.Threading.Monitor]::Enter($StatsLock)
            try {
                switch ($Type) {
                    "Processed" { $StatsRef.Value.ProcessedCount++ }
                    "Success" { $StatsRef.Value.SuccessCount++ }
                    "Failure" { $StatsRef.Value.FailureCount++ }
                    "Retry" { $StatsRef.Value.RetryCount++ }
                }
            }
            finally {
                [System.Threading.Monitor]::Exit($StatsLock)
            }
        }
        
        # 执行查询
        $result = Get-RemoteHostInfo -ComputerName $_ -Credential $Credential -TimeoutSeconds $TimeoutSeconds -MaxRetries $MaxRetries
        
        # 更新统计（使用线程安全方式）
        Update-Stats -Type "Processed"
        if ($result.Status -eq "成功") {
            Update-Stats -Type "Success"
        } else {
            Update-Stats -Type "Failure"
        }
        
        # 添加结果
        [System.Threading.Monitor]::Enter($StatsLock)
        try {
            [void]$ResultsRef.Value.Add($result)
        } finally {
            [System.Threading.Monitor]::Exit($StatsLock)
        }
        
        # 显示进度（需要重新读取统计信息）
        [System.Threading.Monitor]::Enter($StatsLock)
        try {
            $processed = $StatsRef.Value.ProcessedCount
            $total = $StatsRef.Value.TotalComputers
        } finally {
            [System.Threading.Monitor]::Exit($StatsLock)
        }
        $percent = if ($total -gt 0) { [math]::Round(($processed / $total) * 100, 1) } else { 0 }
        Write-Log "[进度: $processed/$total ($percent%)] $_ - $($result.Status)" -Level "PROGRESS"
        
        return $result
    } -ThrottleLimit $MaxConcurrency
}
else {
    # PowerShell 5.1 使用 Start-Job
    Write-Log "使用 PowerShell 5.1 Start-Job 并行处理模式" -Level "INFO"
    
    $jobs = @()
    $jobIndex = 0
    
    foreach ($computer in $computers) {
        # 控制并发数量
        while (($jobs | Where-Object { $_.State -eq "Running" }).Count -ge $MaxConcurrency) {
            Start-Sleep -Milliseconds 500
            # 收集已完成的任务结果
            $completedJobs = $jobs | Where-Object { $_.State -ne "Running" }
            foreach ($job in $completedJobs) {
                if ($jobs -contains $job) {
                    try {
                        $result = Receive-Job -Job $job -ErrorAction Stop
                        if ($result) {
                            # 更新统计
                            Update-Stats -Type "Processed"
                            if ($result.Status -eq "成功") {
                                Update-Stats -Type "Success"
                            }
                            else {
                                Update-Stats -Type "Failure"
                            }
                            
                            # 添加结果
                            [System.Threading.Monitor]::Enter($script:StatsLock)
                            try {
                                [void]$script:Results.Add($result)
                            }
                            finally {
                                [System.Threading.Monitor]::Exit($script:StatsLock)
                            }
                            
                            # 显示进度
                            $processed = $script:Stats.ProcessedCount
                            $total = $script:Stats.TotalComputers
                            $percent = if ($total -gt 0) { [math]::Round(($processed / $total) * 100, 1) } else { 0 }
                            Write-Log "[进度: $processed/$total ($percent%)] $($result.ComputerName) - $($result.Status)" -Level "PROGRESS"
                        }
                        Remove-Job -Job $job -Force
                        $jobs = $jobs | Where-Object { $_ -ne $job }
                    }
                    catch {
                        Write-Log "处理作业结果失败: $($_.Exception.Message)" -Level "WARNING"
                    }
                }
            }
        }
        
        # 启动新作业
        $job = Start-Job -ScriptBlock {
            param($ComputerName, $Credential, $TimeoutSeconds, $MaxRetries, $LogFile, $LogLock)
            
            # 设置变量
            $script:LogLock = $LogLock
            
            # 定义函数（在作业中需要重新定义）
            function Write-Log {
                param([AllowEmptyString()][string]$Message = "", [string]$Level = "INFO")
                # 如果消息为空，只写入空行到日志文件，不输出到控制台
                if ([string]::IsNullOrWhiteSpace($Message)) {
                    [System.Threading.Monitor]::Enter($script:LogLock)
                    try {
                        Add-Content -Path $LogFile -Value "" -ErrorAction SilentlyContinue
                    }
                    finally {
                        [System.Threading.Monitor]::Exit($script:LogLock)
                    }
                    return
                }
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                $logEntry = "[$timestamp] [JOB] [$Level] $Message"
                [System.Threading.Monitor]::Enter($script:LogLock)
                try {
                    if ($Level -ne "DEBUG") {
                        switch ($Level) {
                            "ERROR" { Write-Host $logEntry -ForegroundColor Red }
                            "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
                            "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
                            "PROGRESS" { Write-Host $logEntry -ForegroundColor Cyan }
                            default { Write-Host $logEntry -ForegroundColor White }
                        }
                    }
                    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
                }
                finally {
                    [System.Threading.Monitor]::Exit($script:LogLock)
                }
            }
            
            function Format-MACAddress {
                param([string]$MACAddress)
                if ([string]::IsNullOrWhiteSpace($MACAddress)) { return "" }
                $mac = $MACAddress -replace '[:\-\s]', ''
                if ($mac -match '^[0-9A-Fa-f]{12}$') {
                    return ($mac -split '(..)' | Where-Object { $_ }) -join '-'
                }
                return $MACAddress
            }
            
            function Test-RemoteHostConnectivity {
                param([string]$ComputerName, [object]$Credential, [int]$MaxRetries, [int]$TimeoutSeconds)
                for ($retry = 0; $retry -le $MaxRetries; $retry++) {
                    try {
                        $sessionOption = New-PSSessionOption -OpenTimeout ($TimeoutSeconds * 1000) -CancelTimeout ($TimeoutSeconds * 500)
                        if ($Credential) {
                            $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ErrorAction Stop
                        } else {
                            $session = New-PSSession -ComputerName $ComputerName -SessionOption $sessionOption -ErrorAction Stop
                        }
                        Remove-PSSession $session
                        return @{ Success = $true; Error = $null; Retries = $retry }
                    } catch {
                        if ($retry -eq $MaxRetries) {
                            return @{ Success = $false; Error = $_.Exception.Message; Retries = $retry }
                        }
                        Start-Sleep -Seconds (2 * ($retry + 1))
                    }
                }
            }
            
            function Get-RemoteHostInfoScriptBlock {
                return {
                    try {
                        $result = @{ ComputerName = $null; IPAddress = $null; MACAddress = $null; Error = $null }
                        $result.ComputerName = $env:COMPUTERNAME
                        if ([string]::IsNullOrWhiteSpace($result.ComputerName)) {
                            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                            $result.ComputerName = $computerSystem.Name
                        }
                        try {
                            $activeAdapter = Get-NetAdapter | Where-Object {
                                $_.Status -eq "Up" -and $_.Virtual -eq $false -and
                                $_.Name -notlike "*Loopback*" -and $_.Name -notlike "*Teredo*" -and $_.Name -notlike "*isatap*"
                            } | Select-Object -First 1
                            if ($activeAdapter) {
                                $ipConfig = Get-NetIPAddress -InterfaceIndex $activeAdapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                                           Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -ne "0.0.0.0" } | Select-Object -First 1
                                if ($ipConfig) {
                                    $result.IPAddress = $ipConfig.IPAddress
                                    $result.MACAddress = $activeAdapter.MacAddress
                                } else { throw "未找到有效的IPv4地址" }
                            } else { throw "未找到活动适配器" }
                        } catch {
                            $networkConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | 
                                             Where-Object { 
                                                 $_.IPEnabled -eq $true -and $_.IPAddress -and $_.MACAddress -and
                                                 $_.IPAddress[0] -ne "127.0.0.1" -and $_.IPAddress[0] -ne "0.0.0.0"
                                             } | Select-Object -First 1
                            if ($networkConfigs) {
                                $result.IPAddress = $networkConfigs.IPAddress[0]
                                $result.MACAddress = $networkConfigs.MACAddress
                            } else { throw "未找到活动的网络适配器" }
                        }
                        return $result
                    } catch {
                        return @{ ComputerName = $null; IPAddress = $null; MACAddress = $null; Error = "执行失败: $($_.Exception.Message)" }
                    }
                }
            }
            
            function Get-RemoteHostInfo {
                param([string]$ComputerName, [object]$Credential, [int]$TimeoutSeconds, [int]$MaxRetries)
                $queryStartTime = Get-Date
                try {
                    $connectivity = Test-RemoteHostConnectivity -ComputerName $ComputerName -Credential $Credential -MaxRetries $MaxRetries -TimeoutSeconds $TimeoutSeconds
                    if (-not $connectivity.Success) {
                        return @{
                            ComputerName = $ComputerName
                            IPAddress = ""
                            MACAddress = ""
                            Status = "失败"
                            ErrorMessage = "WinRM连接失败: $($connectivity.Error)"
                            QueryTime = (Get-Date) - $queryStartTime
                        }
                    }
                    $sessionOption = New-PSSessionOption -OpenTimeout ($TimeoutSeconds * 1000) -OperationTimeout ($TimeoutSeconds * 1000)
                    $scriptBlock = Get-RemoteHostInfoScriptBlock
                    if ($Credential) {
                        $remoteResult = Invoke-Command -ComputerName $ComputerName -Credential $Credential -SessionOption $sessionOption -ScriptBlock $scriptBlock -ErrorAction Stop
                    } else {
                        $remoteResult = Invoke-Command -ComputerName $ComputerName -SessionOption $sessionOption -ScriptBlock $scriptBlock -ErrorAction Stop
                    }
                    if ($remoteResult.Error) {
                        return @{
                            ComputerName = if ($remoteResult.ComputerName) { $remoteResult.ComputerName } else { $ComputerName }
                            IPAddress = ""
                            MACAddress = ""
                            Status = "失败"
                            ErrorMessage = $remoteResult.Error
                            QueryTime = (Get-Date) - $queryStartTime
                        }
                    }
                    $formattedMAC = Format-MACAddress -MACAddress $remoteResult.MACAddress
                    return @{
                        ComputerName = $remoteResult.ComputerName
                        IPAddress = $remoteResult.IPAddress
                        MACAddress = $formattedMAC
                        Status = "成功"
                        ErrorMessage = ""
                        QueryTime = (Get-Date) - $queryStartTime
                    }
                } catch {
                    return @{
                        ComputerName = $ComputerName
                        IPAddress = ""
                        MACAddress = ""
                        Status = "失败"
                        ErrorMessage = "查询失败: $($_.Exception.Message)"
                        QueryTime = (Get-Date) - $queryStartTime
                    }
                }
            }
            
            # 执行查询
            $result = Get-RemoteHostInfo -ComputerName $ComputerName -Credential $Credential -TimeoutSeconds $TimeoutSeconds -MaxRetries $MaxRetries
            
            # 记录日志
            Write-Log "$ComputerName - $($result.Status)" -Level "PROGRESS"
            
            return $result
        } -ArgumentList $computer, $Credential, $TimeoutSeconds, $MaxRetries, $LogFile, $script:LogLock
        
        $jobs += $job
        $jobIndex++
    }
    
    # 等待所有作业完成
    Write-Log "等待所有作业完成..." -Level "INFO"
    while (($jobs | Where-Object { $_.State -eq "Running" }).Count -gt 0) {
        Start-Sleep -Seconds 1
        $completedJobs = $jobs | Where-Object { $_.State -ne "Running" }
        foreach ($job in $completedJobs) {
            if ($jobs -contains $job) {
                try {
                    $result = Receive-Job -Job $job -ErrorAction Stop
                    if ($result) {
                        # 更新统计
                        Update-Stats -Type "Processed"
                        if ($result.Status -eq "成功") {
                            Update-Stats -Type "Success"
                        }
                        else {
                            Update-Stats -Type "Failure"
                        }
                        
                        # 添加结果
                        [System.Threading.Monitor]::Enter($script:StatsLock)
                        try {
                            [void]$script:Results.Add($result)
                        }
                        finally {
                            [System.Threading.Monitor]::Exit($script:StatsLock)
                        }
                        
                        # 显示进度
                        $processed = $script:Stats.ProcessedCount
                        $total = $script:Stats.TotalComputers
                        $percent = if ($total -gt 0) { [math]::Round(($processed / $total) * 100, 1) } else { 0 }
                        Write-Log "[进度: $processed/$total ($percent%)] $($result.ComputerName) - $($result.Status)" -Level "PROGRESS"
                    }
                    Remove-Job -Job $job -Force
                    $jobs = $jobs | Where-Object { $_ -ne $job }
                }
                catch {
                    Write-Log "处理作业结果失败: $($_.Exception.Message)" -Level "WARNING"
                }
            }
        }
    }
    
    # 清理剩余作业
    $remainingJobs = Get-Job | Where-Object { $_.State -ne "Completed" }
    if ($remainingJobs) {
        $remainingJobs | Remove-Job -Force
    }
}

# 导出结果到CSV
Write-Log "" -Level "INFO"
Write-Log "正在导出结果到CSV..." -Level "INFO"
$exportSuccess = Export-ResultsToCSV -OutputPath $OutputCSV -Results $script:Results

# 显示统计信息
$scriptEndTime = Get-Date
$totalTime = $scriptEndTime - $ScriptStartTime

Write-Log "" -Level "INFO"
Write-Log "========================================" -Level "INFO"
Write-Log "查询完成 - 统计信息" -Level "INFO"
Write-Log "========================================" -Level "INFO"
Write-Log "总计算机数: $($script:Stats.TotalComputers)" -Level "INFO"
Write-Log "成功查询: $($script:Stats.SuccessCount)" -Level "SUCCESS"
Write-Log "失败查询: $($script:Stats.FailureCount)" -Level "ERROR"
Write-Log "总耗时: $([math]::Round($totalTime.TotalSeconds, 2)) 秒" -Level "INFO"
Write-Log "输出文件: $OutputCSV" -Level "INFO"
Write-Log "日志文件: $LogFile" -Level "INFO"
Write-Log "========================================" -Level "INFO"

if ($exportSuccess) {
    Write-Log "脚本执行完成！" -Level "SUCCESS"
    exit 0
}
else {
    Write-Log "脚本执行完成，但CSV导出失败！" -Level "WARNING"
    exit 1
}

