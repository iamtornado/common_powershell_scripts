#Requires -Version 5.1

<#
.SYNOPSIS
    在域控 Security 日志中按用户排查账户锁定来源（IP、工作站名、Caller Computer 等）。

.DESCRIPTION
    读取指定时间范围内的 4740（账户锁定），并可选用 4625、4771、4776 辅助定位失败登录来源。
    建议在具有读取域控安全日志权限的账号下运行；从成员机执行时需指定 -ComputerName 为 PDC 或任一 DC。

.PARAMETER UserName
    要排查的 sAMAccountName（可写 zhangsan 或 DOMAIN\zhangsan）。匹配不区分大小写。

.PARAMETER Days
    自当前时间向前追溯的天数（默认 7）。

.PARAMETER ComputerName
    要查询的域控制器。省略时尝试解析当前域的 PDC Emulator。

.PARAMETER Credential
    连接域控时使用的凭据。指定后通过 Invoke-Command 在目标计算机上执行查询（含本机指定其他凭据的场景）。

.PARAMETER OutputDirectory
    导出 CSV 的目录。默认：当前目录下 LockoutInvestigation_yyyyMMdd_HHmmss。

.PARAMETER LockoutMaxEvents
    4740 最大条数（防止极繁忙环境一次拉取过多）。

.PARAMETER FailureMaxEvents
    4625 / 4771 / 4776 各自最大条数（在时间窗口内截断）。

.PARAMETER IncludeFailedLogons
    是否包含 4625 失败登录（默认 $true）。关闭：-IncludeFailedLogons:$false

.PARAMETER IncludeKerberos4771
    是否包含 4771 Kerberos 预认证失败（默认 $true）。关闭：-IncludeKerberos4771:$false

.PARAMETER IncludeNtlm4776
    是否包含 4776 凭据验证（默认 $true）。关闭：-IncludeNtlm4776:$false

.PARAMETER PassThru
    将结果对象写入管道，便于后续处理。

.EXAMPLE
    .\Get-ADAccountLockoutSource.ps1 -UserName zhangsan

.EXAMPLE
    .\Get-ADAccountLockoutSource.ps1 -UserName zhangsan -Days 3 -ComputerName dc01.contoso.com -OutputDirectory D:\Reports\Lockout

.EXAMPLE
    $c = Get-Credential
    .\Get-ADAccountLockoutSource.ps1 -UserName zhangsan -ComputerName dc01.contoso.com -Credential $c

.NOTES
    Author: tornadoami
    需要：对目标域控 Security 日志的读取权限；高级审核策略需已记录相应失败事件，否则 IP/工作站字段可能为空。
    本文件为 UTF-8（带 BOM）；若编辑器去掉 BOM，Windows PowerShell 5.1 可能误解析中文导致语法错误。
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserName,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$Days = 7,

    [Parameter(Mandatory = $false)]
    [string]$ComputerName,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 500000)]
    [int]$LockoutMaxEvents = 5000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1000, 500000)]
    [int]$FailureMaxEvents = 25000,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeFailedLogons = $true,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeKerberos4771 = $true,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeNtlm4776 = $true,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PdcEmulatorHostName {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        return $domain.PdcRoleOwner.Name
    }
    catch {
        throw "无法自动解析 PDC Emulator（当前计算机可能未加入域）。请使用 -ComputerName 指定域控。详情: $($_.Exception.Message)"
    }
}

function Test-IsLocalComputerName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $n = $Name.Trim()
    if ($n -ieq 'localhost' -or $n -eq '.' -or $n -ieq $env:COMPUTERNAME) { return $true }
    try {
        $h = [System.Net.Dns]::GetHostEntry('127.0.0.1')
        foreach ($a in $h.Aliases) {
            if ($n -ieq $a) { return $true }
        }
        if ($n -ieq $h.HostName) { return $true }
    }
    catch { }
    try {
        $me = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)
        if ($n -ieq $me.HostName) { return $true }
    }
    catch { }
    return $false
}

function Get-SamAccountNameFromEventField {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $s = $Raw.Trim()
    if ($s.Contains('\')) { return ($s -split '\\', 2)[1] }
    return $s
}

$script:CollectLockoutEvidenceSb = {
    param(
        [DateTime]$StartTime,
        [string]$UserSam,
        [int]$LockoutMax,
        [int]$FailureMax,
        [bool]$Want4625,
        [bool]$Want4771,
        [bool]$Want4776
    )

    $evtAccountNameKey = 'Account Name'

    function ConvertTo-EventDataMap {
        param([Parameter(Mandatory = $true)] $EventRecord)
        $map = @{}
        $xml = [xml]$EventRecord.ToXml()
        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name) { $map[$node.Name] = $node.InnerText }
        }
        $map
    }

    function Get-SamFromRaw {
        param([string]$Raw)
        if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
        $s = $Raw.Trim()
        if ($s.Contains('\')) { return ($s -split '\\', 2)[1] }
        return $s
    }

    $base = @{ LogName = 'Security'; StartTime = $StartTime }

    $list4740 = [System.Collections.Generic.List[object]]::new()
    $f0 = $base.Clone()
    $f0['Id'] = 4740
    foreach ($ev in (Get-WinEvent -FilterHashtable $f0 -MaxEvents $LockoutMax -ErrorAction Stop)) {
        $d = ConvertTo-EventDataMap -EventRecord $ev
        $target = $d['TargetUserName']
        if (-not $target) { continue }
        if ($target -ine $UserSam) { continue }
        $list4740.Add([pscustomobject]@{
                TimeCreated        = $ev.TimeCreated
                EventId            = 4740
                TargetUserName     = $target
                TargetDomainName   = $d['TargetDomainName']
                CallerComputerName = $d['CallerComputerName']
                TargetSid          = $d['TargetSid']
            })
    }

    $list4625 = [System.Collections.Generic.List[object]]::new()
    if ($Want4625) {
        $f = $base.Clone()
        $f['Id'] = 4625
        foreach ($ev in (Get-WinEvent -FilterHashtable $f -MaxEvents $FailureMax -ErrorAction Stop)) {
            $d = ConvertTo-EventDataMap -EventRecord $ev
            $target = $d['TargetUserName']
            if (-not $target) { continue }
            if ($target -ine $UserSam) { continue }
            $list4625.Add([pscustomobject]@{
                    TimeCreated               = $ev.TimeCreated
                    EventId                   = 4625
                    TargetUserName            = $target
                    IpAddress                 = $d['IpAddress']
                    WorkstationName           = $d['WorkstationName']
                    LogonType                 = $d['LogonType']
                    Status                    = $d['Status']
                    SubStatus                 = $d['SubStatus']
                    ProcessName               = $d['ProcessName']
                    AuthenticationPackageName = $d['AuthenticationPackageName']
                })
        }
    }

    $list4771 = [System.Collections.Generic.List[object]]::new()
    if ($Want4771) {
        $f = $base.Clone()
        $f['Id'] = 4771
        foreach ($ev in (Get-WinEvent -FilterHashtable $f -MaxEvents $FailureMax -ErrorAction Stop)) {
            $d = ConvertTo-EventDataMap -EventRecord $ev
            $target = $d['TargetUserName']
            if (-not $target) { continue }
            if ($target -ine $UserSam) { continue }
            $list4771.Add([pscustomobject]@{
                    TimeCreated    = $ev.TimeCreated
                    EventId        = 4771
                    TargetUserName = $target
                    Status         = $d['Status']
                    IpAddress      = $d['IpAddress']
                    ServiceName    = $d['ServiceName']
                })
        }
    }

    $list4776 = [System.Collections.Generic.List[object]]::new()
    if ($Want4776) {
        $f = $base.Clone()
        $f['Id'] = 4776
        foreach ($ev in (Get-WinEvent -FilterHashtable $f -MaxEvents $FailureMax -ErrorAction Stop)) {
            $d = ConvertTo-EventDataMap -EventRecord $ev
            $acct = $d['TargetUserName']
            if (-not $acct) { $acct = $d[$evtAccountNameKey] }
            $sam = Get-SamFromRaw -Raw $acct
            if (-not $sam) { continue }
            if ($sam -ine $UserSam) { continue }
            $list4776.Add([pscustomobject]@{
                    TimeCreated    = $ev.TimeCreated
                    EventId        = 4776
                    TargetUserName = $sam
                    AccountRaw     = $acct
                    Workstation    = $d['Workstation']
                    Status         = $d['Status']
                })
        }
    }

    [pscustomobject]@{
        Events4740 = @($list4740 | Sort-Object TimeCreated)
        Events4625 = @($list4625 | Sort-Object TimeCreated)
        Events4771 = @($list4771 | Sort-Object TimeCreated)
        Events4776 = @($list4776 | Sort-Object TimeCreated)
    }
}

$userFilter = $UserName.Trim()
$userFilter = Get-SamAccountNameFromEventField -Raw $userFilter

if ([string]::IsNullOrWhiteSpace($ComputerName)) {
    $ComputerName = Get-PdcEmulatorHostName
    Write-Verbose "未指定 -ComputerName，使用 PDC: $ComputerName"
}

$useRemoting = (-not (Test-IsLocalComputerName -Name $ComputerName)) -or ($null -ne $Credential)
if ($useRemoting) {
    Write-Verbose "通过 Invoke-Command 查询: $ComputerName"
}

$startTime = (Get-Date).AddDays(-$Days)
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path (Get-Location) ('LockoutInvestigation_{0:yyyyMMdd_HHmmss}' -f (Get-Date))
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$invokeArgs = @(
    $startTime,
    $userFilter,
    $LockoutMaxEvents,
    $FailureMaxEvents,
    $IncludeFailedLogons,
    $IncludeKerberos4771,
    $IncludeNtlm4776
)

if ($useRemoting) {
    $icParams = @{
        ComputerName = $ComputerName
        ScriptBlock  = $script:CollectLockoutEvidenceSb
        ArgumentList = $invokeArgs
    }
    if ($Credential) { $icParams['Credential'] = $Credential }
    $bundle = Invoke-Command @icParams
}
else {
    $bundle = & $script:CollectLockoutEvidenceSb @invokeArgs
}

$events4740 = @($bundle.Events4740)
$events4625 = @($bundle.Events4625)
$events4771 = @($bundle.Events4771)
$events4776 = @($bundle.Events4776)

$csv4740 = Join-Path $OutputDirectory 'Lockout_4740.csv'
$csv4625 = Join-Path $OutputDirectory 'FailedLogon_4625.csv'
$csv4771 = Join-Path $OutputDirectory 'KerberosPreAuthFailed_4771.csv'
$csv4776 = Join-Path $OutputDirectory 'CredentialValidation_4776.csv'

if ($events4740.Count -gt 0) {
    $events4740 | Export-Csv -LiteralPath $csv4740 -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning "在时间范围内未找到用户 '$userFilter' 的 4740 锁定事件（或已达 -LockoutMaxEvents 上限）。"
}

if ($IncludeFailedLogons) {
    if ($events4625.Count -gt 0) { $events4625 | Export-Csv -LiteralPath $csv4625 -NoTypeInformation -Encoding UTF8 }
}
if ($IncludeKerberos4771) {
    if ($events4771.Count -gt 0) { $events4771 | Export-Csv -LiteralPath $csv4771 -NoTypeInformation -Encoding UTF8 }
}
if ($IncludeNtlm4776) {
    if ($events4776.Count -gt 0) { $events4776 | Export-Csv -LiteralPath $csv4776 -NoTypeInformation -Encoding UTF8 }
}

Write-Host "查询域控: $ComputerName | 用户: $userFilter | 回溯: $Days 天"
Write-Host "输出目录: $OutputDirectory"
Write-Host "4740 条数: $($events4740.Count) | 4625: $($events4625.Count) | 4771: $($events4771.Count) | 4776: $($events4776.Count)"

if ($PassThru) {
    [pscustomobject]@{
        ComputerName    = $ComputerName
        UserName        = $userFilter
        Lockouts4740    = $events4740
        Failed4625      = $events4625
        Kerberos4771    = $events4771
        Ntlm4776        = $events4776
        OutputDirectory = $OutputDirectory
    }
}
