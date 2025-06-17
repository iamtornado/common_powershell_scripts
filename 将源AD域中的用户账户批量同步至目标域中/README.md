# AD域用户批量同步工具

## 项目概述
此PowerShell脚本用于将源Active Directory域中的用户账户批量同步至目标AD域，支持用户属性映射、重复账户检测、错误日志记录等功能。

## 功能特性
- 从指定源域OU批量获取用户信息
- 自动处理用户邮箱地址映射
- 目标域账户创建状态跟踪
- 详细错误日志记录
- 支持凭据认证与权限检查
- 跳过已存在账户（不计数为错误）

## 前置要求
- Windows PowerShell 5.1 或更高版本
- Active Directory模块（`ActiveDirectory`）
- 源域和目标域的网络连通性
- 具有源域读取权限和目标域用户创建权限的账户

## 使用方法
### 基本语法
```powershell
.\将源AD域中的用户账户批量同步至目标域中.ps1 -SourceDomain <源域名> -SourceOU <源OU路径> -TargetDomain <目标域名> -TargetOU <目标OU路径> -TargetUPNSuffix <目标UPN后缀> -DefaultPassword <安全字符串> -TargetCredential <凭据对象>
```

### 示例
```powershell
# 创建安全密码
$password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

# 获取目标域凭据
$cred = Get-Credential

# 执行同步
.\将源AD域中的用户账户批量同步至目标域中.ps1 -SourceDomain contoso.com -SourceOU "OU=Users,DC=contoso,DC=com" -TargetDomain fabrikam.com -TargetOU "OU=ImportedUsers,DC=fabrikam,DC=com" -TargetUPNSuffix "@fabrikam.com" -DefaultPassword $password -TargetCredential $cred
```

## 参数说明
| 参数名           | 类型           | 描述                                  | 是否必需 |
|------------------|----------------|---------------------------------------|----------|
| SourceDomain     | String         | 源AD域名（如：contoso.com）           | 是       |
| SourceOU         | String         | 源域用户所在OU的LDAP路径              | 是       |
| TargetDomain     | String         | 目标AD域名（如：fabrikam.com）        | 是       |
| TargetOU         | String         | 目标域存放用户的OU的LDAP路径          | 是       |
| TargetUPNSuffix  | String         | 目标用户UPN后缀（如：@fabrikam.com）  | 是       |
| DefaultPassword  | SecureString   | 创建用户时使用的默认密码              | 是       |
| TargetCredential | PSCredential   | 用于目标域认证的凭据对象              | 是       |

## 日志文件
脚本执行过程中会生成详细日志，默认路径为：
```
<脚本所在目录>\ADSyncErrors.log
```
日志内容包括：错误时间、受影响用户、错误类型及详细描述。

## 注意事项
1. **安全提示**：生产环境中应使用安全的密码管理方式，避免硬编码密码
2. **权限要求**：确保运行脚本的账户具有足够权限
3. **OU路径格式**：必须使用标准LDAP格式（如：`OU=Users,DC=domain,DC=com`）
4. **网络要求**：源域和目标域之间需开放LDAP相关端口（389/636）

## 错误处理
| 错误类型               | 处理方式                          |
|------------------------|-----------------------------------|
| 账户已存在             | 跳过并记录警告（不计入错误计数）  |
| 权限不足               | 记录错误并继续执行                |
| OU不存在或不可访问     | 脚本终止并显示错误信息            |
| 网络连接失败           | 脚本终止并显示错误信息            |

## 版本历史
- v1.0: 初始版本，支持基本用户同步功能