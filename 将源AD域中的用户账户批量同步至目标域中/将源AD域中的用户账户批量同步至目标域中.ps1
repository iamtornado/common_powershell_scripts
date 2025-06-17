<#
.SYNOPSIS
将源Active Directory域中的用户账户批量同步至目标域

.DESCRIPTION
此脚本从指定的源域OU中获取用户账户信息，并将其批量创建到目标域的指定OU中。
支持邮件地址处理、重复账户检测和操作结果统计。

.PARAMETER SourceDomain
源Active Directory域名（例如：contoso.com）

.PARAMETER SourceOU
源域中要同步的用户所在的OU完整路径（例如："OU=Users,DC=contoso,DC=com"）

.PARAMETER TargetDomain
目标Active Directory域名（例如：fabrikam.com）

.PARAMETER TargetOU
目标域中用于存放同步用户的OU完整路径（例如："OU=ImportedUsers,DC=fabrikam,DC=com"）

.PARAMETER TargetUPNSuffix
目标域用户的UPN后缀（例如："@fabrikam.com"）

.PARAMETER DefaultPassword
创建目标域用户时使用的默认密码

.PARAMETER TargetCredential
用于连接目标域的凭据对象，需具有创建用户的权限

.EXAMPLE
PS> .\将源AD域中的用户账户批量同步至目标域中.ps1 -SourceDomain contoso.com -SourceOU "OU=Users,DC=contoso,DC=com" -TargetDomain fabrikam.com -TargetOU "OU=ImportedUsers,DC=fabrikam,DC=com" -TargetUPNSuffix "@fabrikam.com" -DefaultPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -TargetCredential (Get-Credential)

.NOTES
Author: tornadoami
微信公众号：AI发烧友
Version: 1.0
Date: $(Get-Date -Format 'yyyy-MM-dd')
#>

# 参数验证
param(
    [Parameter(Mandatory=$true)]
    [string]$SourceDomain,

    [Parameter(Mandatory=$true)]
    [string]$SourceOU,

    [Parameter(Mandatory=$true)]
    [string]$TargetDomain,

    [Parameter(Mandatory=$true)]
    [string]$TargetOU,

    [Parameter(Mandatory=$true)]
    [string]$TargetUPNSuffix,

    [Parameter(Mandatory=$true)]
    [SecureString]$DefaultPassword,

    [Parameter(Mandatory=$true)]
    [pscredential]$TargetCredential
)

# 导入Active Directory模块
# 若模块不存在或加载失败，脚本将终止执行
Import-Module ActiveDirectory -ErrorAction Stop

# 日志文件配置
$LogFileName = "ADSyncErrors.log"
$LogFilePath = [System.IO.Path]::GetFullPath($LogFileName)
Write-Host "日志文件将保存至: $LogFilePath" -ForegroundColor Gray

# 配置参数区域
# 参数值已通过命令行参数传入，此处无需再次赋值
  # 如需修改默认值，请在调用脚本时使用参数指定
  # 例如: -SourceDomain "contoso.com" -SourceOU "OU=Users,DC=contoso,DC=com"

# 注意：以下硬编码密码仅为示例，生产环境中必须使用安全的密码管理方式
# 建议使用 Read-Host -AsSecureString 或从安全的密钥管理服务获取密码
# $DefaultPassword = Read-Host -Prompt "请输入默认密码" -AsSecureString

# 获取源域用户信息
# 使用Get-ADUser cmdlet从源域指定OU中检索用户对象
# -Filter *: 获取所有用户
# -SearchBase: 指定搜索的起始OU
# -SearchScope Subtree: 包括所有子OU
# -Server: 指定源域控制器
# -Properties: 指定需要额外获取的用户属性
# 验证源OU格式是否正确
    if (-not $SourceOU.StartsWith('OU=') -or -not $SourceOU.Contains('DC=')) {
        Write-Host "错误：源OU路径格式不正确，请使用LDAP格式（例如：OU=Users,DC=contoso,DC=com）" -ForegroundColor Red
        exit 1
    }

    # 验证目标OU格式是否正确
    if (-not $TargetOU.StartsWith('OU=') -or -not $TargetOU.Contains('DC=')) {
        Write-Host "错误：目标OU路径格式不正确，请使用LDAP格式（例如：OU=ImportedUsers,DC=fabrikam,DC=com）" -ForegroundColor Red
        exit 1
    }

    # 验证目标OU是否存在
    try {
        Get-ADOrganizationalUnit -Identity $TargetOU -Server $TargetDomain -Credential $TargetCredential -ErrorAction Stop
    } catch {
        Write-Host "错误：目标OU不存在或无法访问 - $_" -ForegroundColor Red
        exit 1
    }

    # 验证UPN后缀格式是否正确
    if (-not $TargetUPNSuffix.StartsWith('@')) {
        Write-Host "错误：UPN后缀必须以@开头（例如：@fabrikam.com）" -ForegroundColor Red
        exit 1
    }

    try {
        # 使用Get-ADUser获取源域用户
        $SourceUsers = Get-ADUser -Filter * `
                                  -SearchBase $SourceOU `
                                  -SearchScope Subtree `
                                  -Server $SourceDomain `
                                  -Properties GivenName, Surname, DisplayName, 
                                              SamAccountName, UserPrincipalName, 
                                              EmailAddress, Enabled, Mail | 
                        Group-Object -Property SamAccountName | ForEach-Object { $_.Group[0] }
        
        Write-Host "成功获取 [$($SourceUsers.Count)] 个源域用户" -ForegroundColor Green

        # 验证是否获取到用户
        if ($SourceUsers.Count -eq 0) {
            Write-Host "警告：在源OU中未找到任何用户，脚本将退出" -ForegroundColor Yellow
            exit 0
        }
    }
catch {
    Write-Host "错误：无法查询源域用户 - $_" -ForegroundColor Red
    exit
}

# 初始化统计变量
$SuccessCount = 0  # 成功创建的用户数量
$ErrorCount = 0    # 失败或跳过的用户数量

# 遍历源域用户集合，逐个创建目标域用户
foreach ($User in $SourceUsers) {
    # 确定用户邮件地址
    # 优先使用mail属性，如果为空则使用EmailAddress属性
    # 若两者都为空，则使用默认格式：SamAccountName@TargetDomain
    $UserEmail = if (-not [string]::IsNullOrEmpty($User.Mail)) {
        $User.Mail
    } elseif (-not [string]::IsNullOrEmpty($User.EmailAddress)) {
        $User.EmailAddress
    } else {
        # 无邮件地址时使用默认模式
        "$($User.SamAccountName)@$TargetDomain"
    }
    
    # 构建New-ADUser命令参数
    $NewUserParams = @{
        Name              = $User.Name               # 用户姓名
        GivenName         = $User.GivenName          # 名
        Surname           = $User.Surname            # 姓
        DisplayName       = $User.DisplayName        # 显示名称
        SamAccountName    = $User.SamAccountName     # SAM账户名
        UserPrincipalName = $User.SamAccountName + $TargetUPNSuffix  # 用户主体名称
        AccountPassword   = $DefaultPassword         # 账户密码
        Path              = $TargetOU                # 目标OU路径
        Enabled           = $User.Enabled            # 是否启用账户
        Server            = $TargetDomain            # 目标域控制器
        Credential         = $TargetCredential         # 目标域认证凭据
        PasswordNeverExpires = $true                 # 设置密码永不过期
        OtherAttributes   = @{
            'mail' = $UserEmail                      # 设置邮件属性
        }
        ErrorAction       = "Stop"                   # 遇到错误时停止执行
    }

    try {
        # 执行创建用户操作
        $NewUser = New-ADUser @NewUserParams -PassThru
        
        # 输出成功信息
        Write-Host "已创建用户: $($NewUser.SamAccountName) [Email: $UserEmail]" -ForegroundColor Cyan
        $SuccessCount++
    }
    catch {
        # 处理重复账户错误
        # 处理特定错误情况
        if ($_.Exception.Message -like "*The specified account already exists*") {  # 账户已存在错误
            Write-Host "跳过重复账户 [$($User.SamAccountName)]" -ForegroundColor Yellow
            # 记录已存在警告到日志（不增加错误计数）
            $errorMsg = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] 警告: 用户 $($User.SamAccountName) 已存在于目标域"
            $errorMsg | Out-File -FilePath $LogFilePath -Append
        } elseif ($_.Exception.Message -like "*access is denied*" -or $_.Exception.Message -like "*拒绝访问*") {  # 权限不足错误
            Write-Host "创建失败 [$($User.SamAccountName)]: 权限不足，请检查运行脚本的账户权限" -ForegroundColor Red
            $ErrorCount++
            # 记录详细错误信息到日志文件
            $errorMsg = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] 权限错误: 创建用户 $($User.SamAccountName) 失败 - $($_.Exception.Message)"
            $errorMsg | Out-File -FilePath $LogFilePath -Append
        } else {  # 其他错误
            Write-Host "创建失败 [$($User.SamAccountName)]: $($_.Exception.Message)" -ForegroundColor Red
            $ErrorCount++
            # 记录详细错误信息到日志文件
            $errorMsg = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] 错误: 创建用户 $($User.SamAccountName) 失败 - $($_.Exception.Message)"
            $errorMsg | Out-File -FilePath $LogFilePath -Append
        }
    }
}

# 输出同步操作摘要报告
Write-Host "`n操作完成！" -ForegroundColor Green
Write-Host "成功创建用户数: $SuccessCount" -ForegroundColor Green
Write-Host "失败/跳过用户数: $ErrorCount" -ForegroundColor ($ErrorCount -eq 0 ? "Green" : "Yellow")
Write-Host "日志文件路径: $LogFilePath" -ForegroundColor Cyan

# 退出脚本
exit 0