$computerName = "win11-24h2-pxe" #或者$computerName = "192.168.124.15"
$users = @()

$logonSessions = Get-WmiObject -Class Win32_LogonSession -ComputerName $computerName |
    Where-Object { $_.LogonType -eq 2 -or $_.LogonType -eq 10 }

foreach ($session in $logonSessions) {
    $logonId = $session.LogonId

    $assocs = Get-WmiObject -Class Win32_LoggedOnUser -ComputerName $computerName |
        Where-Object { $_.Dependent -match "LogonId=`"$logonId`"" }

    foreach ($assoc in $assocs) {
        try {
            $userObj = [WMI]$assoc.Antecedent
            $fullName = "$($userObj.Domain)\$($userObj.Name)"

            # 排除系统虚拟账户 + 去重
            if ($fullName -notmatch '^DWM-|^UMFD-' -and $users -notcontains $fullName) {
                $users += $fullName
            }
        } catch {
            # 忽略解析失败的对象（例如无效路径）
        }
    }
}

$users