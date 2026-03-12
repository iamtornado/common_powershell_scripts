<#
.SYNOPSIS
    查询活动目录(AD)中指定组的成员信息并导出为 CSV 文件。

.DESCRIPTION
    对提供的 AD 组列表，递归查询每个组下的成员（用户），收集用户名（工号）、姓名、OU 等信息，
    并导出为 CSV 文件。支持嵌套组中的用户。

.PARAMETER GroupNames
    要查询的 AD 组名称列表。可与 -GroupFile 二选一。

.PARAMETER GroupFile
    包含组名列表的文本文件路径（每行一个组名）。与 -GroupNames 二选一；若指定则忽略 -GroupNames。

.PARAMETER OutputPath
    导出 CSV 文件的路径。默认：当前目录下 "ADGroupMembers_yyyyMMdd_HHmmss.csv"。

.PARAMETER Server
    指定域控制器（可选）。不指定时使用当前域默认 DC。

.PARAMETER Credential
    用于查询 AD 的凭据（可选）。不指定时使用当前用户身份。

.PARAMETER DebugMode
    打开调试输出：在控制台和调试日志文件中输出组列表、每组写入行数、累计行数、导出前统计等，便于排查“只导出一个组”等问题。

.EXAMPLE
    .\Export-ADGroupMembers.ps1 -GroupNames "g.mybox.admin","g.offshore.all"

.EXAMPLE
    .\Export-ADGroupMembers.ps1 -GroupFile "d:\groups.txt" -OutputPath "members.csv"

.EXAMPLE
    .\Export-ADGroupMembers.ps1 -GroupFile "d:\groups.txt" -OutputPath "members.csv" -DebugMode

.NOTES
    Author: tornadoami
    Version: 1.0
    Date: 2025-03-12
    需要：Active Directory PowerShell 模块，以及域内查询组/用户的权限。
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$GroupNames = @(
        'g.test.test'

    ),

    [Parameter(Mandatory = $false)]
    [string]$GroupFile = $null,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path (Get-Location) ("ADGroupMembers_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))),

    [Parameter(Mandatory = $false)]
    [string]$Server = $null,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential = $null,

    [Parameter(Mandatory = $false)]
    [switch]$DebugMode
)

# 调试：统一输出并可选写入日志（仅在 -DebugMode 时使用）
$script:DebugLogLines = [System.Collections.Generic.List[string]]::new()
function Write-Diag {
    param([string]$Message, [string]$Level = 'Info')
    if (-not $DebugMode) { return }
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $line = "[$ts][$Level] $Message"
    $script:DebugLogLines.Add($line) | Out-Null
    $color = switch ($Level) { 'Warn' { 'Yellow' } 'Error' { 'Red' } default { 'DarkGray' } }
    Write-Host "  [调试] $Message" -ForegroundColor $color
}

# 确定组列表：-GroupFile 优先，否则用 -GroupNames（强制为数组，避免单元素时被当成标量）
if (-not [string]::IsNullOrWhiteSpace($GroupFile) -and (Test-Path -LiteralPath $GroupFile)) {
    $GroupNamesToUse = @(Get-Content -LiteralPath $GroupFile -Encoding UTF8 | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique)
} else {
    $GroupNamesToUse = @($GroupNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

if (-not $GroupNamesToUse -or $GroupNamesToUse.Count -eq 0) {
    Write-Warning "未提供任何组名（且未指定有效 -GroupFile），脚本退出。"
    return
}

# 调试：组列表来源与内容
Write-Diag "组列表来源: $(if ($GroupFile) { "GroupFile='$GroupFile'" } else { 'GroupNames 参数' })"
Write-Diag "GroupNamesToUse 类型: $($GroupNamesToUse.GetType().FullName), Count: $($GroupNamesToUse.Count)"
if ($GroupNamesToUse.Count -le 20) {
    Write-Diag "组列表: $($GroupNamesToUse -join ' | ')"
} else {
    Write-Diag "组列表(前5): $($GroupNamesToUse[0..4] -join ' | ')"
    Write-Diag "组列表(后5): $($GroupNamesToUse[-5..-1] -join ' | ')"
}

# 导入 Active Directory 模块
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "未找到 Active Directory 模块，请确保在域控制器或已安装 RSAT 的客户端上运行。"
    return
}
Import-Module ActiveDirectory -ErrorAction Stop

# 构建 Get-ADUser / Get-ADGroupMember 的公共参数
$adCommonParams = @{}
if ($Server) { $adCommonParams['Server'] = $Server }
if ($Credential) { $adCommonParams['Credential'] = $Credential }

Write-Host "将查询以下 $($GroupNamesToUse.Count) 个组: $($GroupNamesToUse -join ', ')" -ForegroundColor Cyan

# 用于汇总结果的列表（每组每用户一行，同一用户在不同组中会有多行）
$allRows = [System.Collections.Generic.List[object]]::new()
$groupIndex = 0

foreach ($groupName in $GroupNamesToUse) {
    $groupName = $groupName.Trim()
    if ([string]::IsNullOrEmpty($groupName)) { continue }
    $groupIndex++
    Write-Diag "--- 开始处理第 $groupIndex/$($GroupNamesToUse.Count) 个组: '$groupName' (当前 allRows 总数: $($allRows.Count))"

    Write-Host "正在查询组: $groupName ..." -ForegroundColor Gray

    try {
        # 获取组对象（用于显示组 DN，若组不存在则跳过）
        $group = Get-ADGroup -Identity $groupName -ErrorAction Stop @adCommonParams
    }
    catch {
        Write-Diag "跳过组 '$groupName'（无法找到）: $_" -Level Warn
        Write-Warning "无法找到组 '$groupName'，已跳过。错误: $_"
        continue
    }

    try {
        # 递归获取组成员（包含嵌套组中的用户）
        $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop @adCommonParams
    }
    catch {
        Write-Diag "跳过组 '$groupName'（获取成员失败）: $_" -Level Warn
        Write-Warning "获取组 '$groupName' 的成员失败，已跳过。错误: $_"
        continue
    }

    # 只处理用户对象（User），忽略计算机、组等
    $userMembers = $members | Where-Object { $_.objectClass -eq 'user' }

    if (-not $userMembers -or $userMembers.Count -eq 0) {
        Write-Diag "组 '$groupName' 无用户成员，跳过写入行。"
        Write-Host "  组内无用户成员。" -ForegroundColor DarkGray
        continue
    }

    # 逐个获取用户详细属性（用户名、姓名、工号、OU 等）
    $userProps = @()
    foreach ($member in $userMembers) {
        $u = Get-ADUser -Identity $member.DistinguishedName -Properties DisplayName, DistinguishedName, EmployeeNumber, EmployeeID, SamAccountName, UserPrincipalName -ErrorAction SilentlyContinue @adCommonParams
        if ($u) { $userProps += $u }
    }

    foreach ($user in $userProps) {
        # 从 DistinguishedName 解析 OU 路径（例如 OU=Users,OU=IT,DC=contoso,DC=com -> IT/Users）
        $ou = ''
        $dnParts = $user.DistinguishedName -split ',(?=(?:OU=|CN=|DC=))'
        $ouParts = $dnParts | Where-Object { $_ -match '^OU=' } | ForEach-Object { ($_ -replace '^OU=([^,]+).*', '$1').Trim() }
        if ($ouParts) {
            [Array]::Reverse($ouParts)
            $ou = $ouParts -join '/'
        }
        else {
            $ou = $user.DistinguishedName
        }

        # 工号：优先 EmployeeNumber，其次 EmployeeID，再 SamAccountName
        $employeeId = $null
        if ($user.EmployeeNumber) { $employeeId = $user.EmployeeNumber }
        elseif ($user.EmployeeID) { $employeeId = $user.EmployeeID }
        if ([string]::IsNullOrWhiteSpace($employeeId)) { $employeeId = $user.SamAccountName }

        $row = [PSCustomObject]@{
            '组名'           = $groupName
            '用户名(工号)'   = $employeeId
            'SamAccountName' = $user.SamAccountName
            '姓名'           = $user.DisplayName
            'OU'             = $ou
            'UserPrincipalName' = $user.UserPrincipalName
            'DistinguishedName' = $user.DistinguishedName
        }
        $allRows.Add($row)
    }

    Write-Diag "组 '$groupName' 本组添加 $($userProps.Count) 行，allRows 累计: $($allRows.Count)"
    Write-Host "  找到 $($userProps.Count) 个用户。" -ForegroundColor Green
}

if ($allRows.Count -eq 0) {
    Write-Host "没有收集到任何用户记录，不生成 CSV。" -ForegroundColor Yellow
    return
}

# 将输出路径解析为绝对路径，避免“打开错文件”的困惑（相对路径以当前工作目录为准）
$OutputPathResolved = $OutputPath
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPathResolved = Join-Path (Get-Location) $OutputPath
}
$OutputPathResolved = [System.IO.Path]::GetFullPath($OutputPathResolved)

# 确保输出目录存在
$outDir = Split-Path -Parent $OutputPathResolved
if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

# 调试：导出前统计
$distinctGroups = ($allRows | Select-Object -ExpandProperty '组名' -Unique | Measure-Object).Count
$distinctGroupNames = $allRows | Select-Object -ExpandProperty '组名' -Unique
Write-Diag "导出前: allRows.Count=$($allRows.Count), 不同组数=$distinctGroups"
Write-Diag "CSV 中将包含的组名: $($distinctGroupNames -join ' | ')"

# 导出 CSV：使用 UTF-8 带 BOM，Excel 才能正确显示中文
# PowerShell 7 (Core) 的 ConvertTo-Csv 返回 string[]（每行一个元素），直接给 WriteAllText 会变成一行；故先合并为单字符串并用 CRLF 换行
$csvLines = $allRows | ConvertTo-Csv -NoTypeInformation
if ($csvLines -is [array]) {
    $csvContent = $csvLines -join "`r`n"
} else {
    $csvContent = [string]$csvLines
    $csvContent = $csvContent -replace "`r?`n", "`r`n"
}
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($OutputPathResolved, $csvContent, $utf8Bom)

# 始终显示完整路径，便于确认打开的是本次导出的文件
$msg = "已导出 " + $allRows.Count + " 条记录（共 " + $distinctGroups + " 个组）到: " + $OutputPathResolved
Write-Host $msg -ForegroundColor Green

# 写入后校验：读回文件检查行数，若不一致则提示可能打开了错误位置的文件
$expectedLines = $allRows.Count + 1
$actualLines = (Get-Content -LiteralPath $OutputPathResolved -Encoding UTF8).Count
if ($actualLines -ne $expectedLines) {
    Write-Warning "校验: 文件行数=$actualLines，预期=$expectedLines（含表头）。请确认打开的是上述完整路径中的文件。"
} else {
    Write-Diag "校验通过: 文件行数=$actualLines（预期 $expectedLines）。"
}

# 调试：写入调试日志文件（与 CSV 同目录，主文件名加 .debug.log）
if ($DebugMode -and $script:DebugLogLines.Count -gt 0) {
    $logPath = [System.IO.Path]::ChangeExtension($OutputPathResolved, '.debug.log')
    $script:DebugLogLines.Insert(0, "Export-ADGroupMembers 调试日志 - $OutputPathResolved")
    $script:DebugLogLines.Insert(1, "生成时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $script:DebugLogLines.Insert(2, "组数: $($GroupNamesToUse.Count), 总行数: $($allRows.Count), CSV 内不同组数: $distinctGroups")
    $script:DebugLogLines.Add("")
    [System.IO.File]::WriteAllLines($logPath, $script:DebugLogLines, $utf8Bom)
    Write-Host "  [调试] 日志已写入: $logPath" -ForegroundColor DarkGray
}
