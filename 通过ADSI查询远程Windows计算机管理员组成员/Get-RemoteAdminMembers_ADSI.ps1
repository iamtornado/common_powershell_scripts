# PowerShell 脚本：通过 ADSI 查询远程 Windows 计算机中本地 Administrators 组的所有成员

<#
.SYNOPSIS
    通过 ADSI 查询远程 Windows 计算机中本地 Administrators 组的所有成员。

.DESCRIPTION
    此脚本使用 ADSI (Active Directory Service Interfaces) 连接到指定的远程计算机，
    并列出该计算机上本地 Administrators 组的所有成员。
    它会尝试处理常见的错误，例如远程计算机无法访问或权限不足。

.PARAMETER ComputerName
    要查询的远程 Windows 计算机的名称或 IP 地址。

.EXAMPLE
    .\Get-RemoteAdminMembers_ADSI.ps1 -ComputerName "RemotePC01"
    这将查询名为 "RemotePC01" 的计算机上的 Administrators 组成员。

.EXAMPLE
    .\Get-RemoteAdminMembers_ADSI.ps1 -ComputerName "192.168.1.100"
    这将查询 IP 地址为 "192.168.1.100" 的计算机上的 Administrators 组成员。

.NOTES
    - 运行此脚本的用户需要具备访问远程计算机的权限。
    - ADSI 访问通常通过 DCOM (Distributed Component Object Model) 进行，
      可能需要确保防火墙允许相关流量 (通常是 TCP 135 和动态端口)。
    - 如果遇到 "访问被拒绝" 错误，请确保当前用户具有足够的权限，
      或者尝试使用具有管理员权限的凭据运行 PowerShell。
    - 此方法对于非域环境或工作组环境中的本地组查询同样有效。
#>

param (
    [Parameter(Mandatory=$true, HelpMessage="请输入要查询的远程计算机的名称或 IP 地址。")]
    [string]$ComputerName
)

Write-Host "正在通过 ADSI 查询远程计算机 '$ComputerName' 上的本地 Administrators 组成员..." -ForegroundColor Cyan

try {
    # 检查远程计算机是否可达 (ping)
    if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -ErrorAction SilentlyContinue)) {
        Write-Error "错误：无法连接到远程计算机 '$ComputerName'。请检查网络连接或计算机名称/IP地址是否正确。"
        exit 1
    }

    # 构建 ADSI 路径以连接到远程计算机的本地 Administrators 组
    # "WinNT://" 是 ADSI 提供程序，用于访问本地用户和组，以及域用户和组
    # "$ComputerName/Administrators,group" 指定了目标计算机上的 Administrators 组
    $group = [ADSI]"WinNT://$ComputerName/Administrators,group"

    Write-Host "成功连接到远程计算机 '$ComputerName' 上的 Administrators 组对象。" -ForegroundColor Green

    $members = @()
    foreach ($member in $group.Members()) {
        $memberType = $member.GetType().InvokeMember("Class", 'GetProperty', $null, $member, $null)
        $memberName = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
        $memberPath = $member.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $member, $null)

        # 尝试从 ADsPath 解析 PrincipalSource
        $principalSource = "Unknown"
        if ($memberPath -like "*WinNT://*/") {
            if ($memberPath -like "*WinNT://$ComputerName/*") {
                $principalSource = "Local"
            } else {
                # 尝试提取域或计算机名
                $match = [regex]::Match($memberPath, 'WinNT://([^/]+)/')
                if ($match.Success) {
                    $sourceName = $match.Groups[1].Value
                    if ($sourceName -ne $ComputerName) {
                        $principalSource = "Domain ($sourceName)"
                    } else {
                        $principalSource = "Local" # 再次确认是本地，以防万一
                    }
                }
            }
        }

        $members += [PSCustomObject]@{
            Name          = $memberName
            Type          = $memberType # 例如：User, Group
            PrincipalSource = $principalSource # 尝试判断来源：Local, Domain
            ADsPath       = $memberPath
        }
    }

    if ($members.Count -gt 0) {
        Write-Host "`n远程计算机 '$ComputerName' 上的 Administrators 组成员：" -ForegroundColor Green
        $members | Format-Table -AutoSize
    }
    else {
        Write-Warning "未在远程计算机 '$ComputerName' 上找到 Administrators 组成员，或者无法获取成员列表。"
    }
}
catch [System.UnauthorizedAccessException] {
    Write-Error "错误：访问远程计算机 '$ComputerName' 被拒绝。请确保您有足够的权限。"
    Write-Error "提示：尝试以管理员身份运行 PowerShell，或检查远程计算机上的用户权限。"
}
catch [System.Management.Automation.RuntimeException] {
    Write-Error "错误：无法通过 ADSI 连接到远程计算机 '$ComputerName' 或获取组信息。"
    Write-Error "详细错误信息：$($_.Exception.Message)"
    Write-Error "提示：请确保远程计算机可达，并且当前用户具有远程访问权限。检查防火墙是否阻止 DCOM 流量。"
}
catch {
    Write-Error "发生未知错误：$($_.Exception.Message)"
    Write-Error "详细错误信息：$($_.Exception | Format-List -Force)"
}

Write-Host "`n脚本执行完毕。" -ForegroundColor DarkGreen
