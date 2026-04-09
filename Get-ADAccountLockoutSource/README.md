# Get-ADAccountLockoutSource

在**域控制器**的 Security 日志中，按**指定域用户（sAMAccountName）**排查账户锁定及失败登录来源，导出 **CSV**，便于定位 **IP**、**工作站名**、**Caller Computer** 等线索。

## 功能

- 查询 **4740**（用户账户被锁定）：含 `TargetUserName`、`CallerComputerName`、`TargetDomainName` 等。
- 可选查询（默认开启，可关闭以加快扫描）：
  - **4625**：登录失败（`IpAddress`、`WorkstationName`、`Status` / `SubStatus`、`LogonType` 等）
  - **4771**：Kerberos 预身份验证失败（含 `IpAddress` 等）
  - **4776**：凭据验证（NTLM 等到 DC），含 `Workstation`；账号字段兼容 `Account Name` / `TargetUserName`
- 未指定域控时，自动解析当前域 **PDC Emulator**；在成员机上可对指定 DC 使用 **WinRM** 远程执行 `Get-WinEvent`（避免事件对象反序列化后无法解析 XML）。
- 支持 **`-Credential`**，通过 `Invoke-Command` 在目标 DC 上以指定账号查询。

## 环境要求

- **Windows PowerShell 5.1**（脚本含 `#Requires -Version 5.1`）
- 运行账号对目标域控的 **Security** 日志有**读取**权限（通常为域管理员或已委派“管理审核和安全日志”等权限的账号）
- 未指定 `-ComputerName` 时，本机需**加入域**，以便通过 `System.DirectoryServices.ActiveDirectory` 解析 PDC；否则请显式传入域控 FQDN
- 从**非域控**远程查询时，需目标 DC **WinRM** 可用，且当前用户对 DC 有相应远程权限
- 域上需已配置**高级审核策略**，否则 4625 / 4771 / 4776 可能缺失或 **IP / 工作站** 字段为空；4740 通常仍有，可先看 `CallerComputerName`

## 文件编码说明

脚本需保存为 **UTF-8（带 BOM）**。若在编辑器中去掉 BOM，在 Windows PowerShell 5.1 下可能误解析中文注释与字符串，出现虚假语法错误（如缺少 `}`）。

## 用法

在脚本所在目录执行（路径按你本机调整）：

```powershell
cd "...\Get-ADAccountLockoutSource"

.\Get-ADAccountLockoutSource.ps1 -UserName zhangsan
```

指定回溯天数、域控与输出目录：

```powershell
.\Get-ADAccountLockoutSource.ps1 -UserName zhangsan -Days 3 `
  -ComputerName dc01.contoso.com -OutputDirectory D:\Reports\Lockout
```

使用其他凭据连接域控：

```powershell
$c = Get-Credential
.\Get-ADAccountLockoutSource.ps1 -UserName zhangsan `
  -ComputerName dc01.contoso.com -Credential $c
```

仅查锁定事件（不拉 4625 / 4771 / 4776，减轻繁忙 DC 压力）：

```powershell
.\Get-ADAccountLockoutSource.ps1 -UserName zhangsan `
  -IncludeFailedLogons:$false -IncludeKerberos4771:$false -IncludeNtlm4776:$false
```

将结果对象放入管道供后续处理：

```powershell
$r = .\Get-ADAccountLockoutSource.ps1 -UserName zhangsan -PassThru
$r.Lockouts4740 | Format-Table
```

**用户名格式**：可写 `zhangsan` 或 `DOMAIN\zhangsan`，脚本会按 sAMAccountName 匹配（不区分大小写）。

## 参数摘要

| 参数 | 说明 |
|------|------|
| `-UserName` | 必填。要排查的域用户 sAMAccountName。 |
| `-Days` | 可选。自当前时间向前追溯天数，默认 `7`，范围 1–365。 |
| `-ComputerName` | 可选。要查询的域控；省略则用当前域 PDC。 |
| `-Credential` | 可选。连接/在 DC 上执行时使用的凭据。 |
| `-OutputDirectory` | 可选。CSV 输出目录；默认当前目录下 `LockoutInvestigation_yyyyMMdd_HHmmss`。 |
| `-LockoutMaxEvents` | 可选。4740 最大条数，默认 `5000`。 |
| `-FailureMaxEvents` | 可选。4625 / 4771 / 4776 各自最大条数，默认 `25000`。 |
| `-IncludeFailedLogons` | 可选。是否包含 4625，默认 `$true`；关闭：`-IncludeFailedLogons:$false`。 |
| `-IncludeKerberos4771` | 可选。是否包含 4771，默认 `$true`。 |
| `-IncludeNtlm4776` | 可选。是否包含 4776，默认 `$true`。 |
| `-PassThru` | 可选。向管道输出包含各事件数组与输出路径的对象。 |

## 输出文件

在 `-OutputDirectory` 目录下（若某类事件无匹配记录则可能不生成对应文件）：

| 文件名 | 内容 |
|--------|------|
| `Lockout_4740.csv` | 账户锁定 |
| `FailedLogon_4625.csv` | 失败登录 |
| `KerberosPreAuthFailed_4771.csv` | Kerberos 预认证失败 |
| `CredentialValidation_4776.csv` | 凭据验证（NTLM 等） |

CSV 为 **UTF-8（带 BOM）**，便于 Excel 打开。

## 排查建议

1. 先看 **4740** 中的 **CallerComputerName**，再在同一时间段对照 **4625 / 4771** 中的 **IP**、**WorkstationName**。
2. 若日志中 **IP 为空**，检查域控高级审核是否记录失败登录细节；可用 **CallerComputerName** 在 DNS/DHCP 中反查。
3. 繁忙域控若频繁达到 `-FailureMaxEvents` 上限，可缩短 `-Days` 或暂时关闭部分 `-Include*` 选项。

## 说明与限制

- 本工具查询的是**域控本地 Security 日志**；多 DC 环境下，锁定与认证可能分散在不同 DC，必要时应对多台 DC 分别执行或集中转发日志（如 SIEM）。
- 不能替代对**客户端本机** Security 日志的分析（例如“谁在这台工作站上交互登录”仍以客户端 4624 为主）。

## 作者

与仓库内其他脚本一致：**tornadoami**（参见脚本内注释）。
