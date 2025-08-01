param (
    [string]$ComputerName = "10.64.9.127"
)

$users = @()
$logonIdMap = @{}
$validLogonTypes = @(2, 10)

# 获取交互式（2）和远程桌面（10）登录的会话
$logonSessions = Get-WmiObject -Class Win32_LogonSession -ComputerName $ComputerName `
    -Authentication PacketPrivacy |
    Where-Object { $validLogonTypes -contains $_.LogonType }

foreach ($session in $logonSessions) {
    $logonIdMap[$session.LogonId] = $true
}

# 预加载用户信息（User-LogonSession关联）
$loggedOnUsers = Get-WmiObject -Class Win32_LoggedOnUser -ComputerName $ComputerName `
    -Authentication PacketPrivacy

foreach ($assoc in $loggedOnUsers) {
    # 提取 LogonId
    if ($assoc.Dependent -match 'LogonId="(\d+)"') {
        $logonId = $matches[1]

        if ($logonIdMap.ContainsKey($logonId)) {
            try {
                $userObj = [WMI]$assoc.Antecedent
                $fullName = "$($userObj.Domain)\$($userObj.Name)"

                if ($fullName -notmatch '^(DWM-|UMFD-)' -and $users -notcontains $fullName) {
                    $users += $fullName
                }
            } catch {
                Write-Warning "忽略解析失败用户：$($_.Exception.Message)"
            }
        }
    }
}

$users
