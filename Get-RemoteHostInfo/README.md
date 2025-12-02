# 远程主机信息查询工具 🔍

> **Remote Host Information Query Tool**  
> 通过WinRM批量查询远程Windows主机的计算机名、IP地址和MAC地址

## 📋 功能概述

这是一个专为IT运维和资产管理设计的PowerShell脚本，能够通过WinRM批量查询远程Windows主机的关键信息，并导出为CSV文件，便于后续分析和处理。

### ✨ 主要特性

- 🔗 **WinRM连接**：使用WinRM协议进行远程连接，安全可靠
- 📊 **批量查询**：支持从文本文件读取计算机列表，批量查询多台主机
- ⚡ **并行处理**：支持并行处理多个主机，提高查询效率（默认100台同时处理，范围1-200）
- 🎯 **信息收集**：自动收集计算机名、IP地址和MAC地址
- 📝 **详细日志**：完善的日志记录机制，记录所有操作和错误信息
- 🔄 **智能重试**：失败自动重试机制，提高成功率
- ⏱️ **超时控制**：可配置的查询超时时间，避免长时间等待
- 📄 **CSV导出**：结果自动导出为CSV文件，便于Excel等工具分析
- 🛡️ **错误处理**：完善的错误处理机制，单个主机失败不影响整体处理
- 🔐 **凭据支持**：支持使用自定义凭据或当前用户凭据连接

## 🚀 快速开始

### 前置要求

1. **PowerShell版本**：PowerShell 5.1 或更高版本
2. **WinRM服务**：目标计算机必须启用并配置WinRM服务
3. **网络连通性**：确保能够通过WinRM连接到目标计算机
4. **权限要求**：需要适当的权限（本地管理员或域管理员）

### WinRM配置

在目标计算机上启用WinRM服务：

```powershell
# 启用WinRM服务（以管理员身份运行）
Enable-PSRemoting -Force

# 或者手动配置
winrm quickconfig
```

确保防火墙规则允许WinRM连接：
- HTTP端口：5985
- HTTPS端口：5986

### 准备计算机列表文件

创建一个文本文件（如 `computers.txt`），每行一个计算机名或IP地址：

```
SERVER01
SERVER02
192.168.1.100
WORKSTATION01
```

## 📖 使用方法

### 基本用法

```powershell
# 使用当前用户凭据查询计算机列表
.\Get-RemoteHostInfo.ps1 -ComputerListFile "C:\computers.txt"
```

### 使用指定凭据

```powershell
# 使用指定凭据连接
$cred = Get-Credential
.\Get-RemoteHostInfo.ps1 -ComputerListFile "C:\computers.txt" -Credential $cred
```

### 指定输出文件

```powershell
# 指定输出CSV文件和日志文件路径
.\Get-RemoteHostInfo.ps1 `
    -ComputerListFile "C:\computers.txt" `
    -OutputCSV "C:\results.csv" `
    -LogFile "C:\query.log"
```

### 并行处理配置

```powershell
# 设置并行处理数量为150（默认100）
.\Get-RemoteHostInfo.ps1 `
    -ComputerListFile "C:\computers.txt" `
    -MaxConcurrency 150
```

### 超时和重试配置

```powershell
# 设置超时时间为60秒，最大重试3次
.\Get-RemoteHostInfo.ps1 `
    -ComputerListFile "C:\computers.txt" `
    -TimeoutSeconds 60 `
    -MaxRetries 3
```

### 完整示例

```powershell
# 完整参数示例
$cred = Get-Credential
.\Get-RemoteHostInfo.ps1 `
    -ComputerListFile "C:\computers.txt" `
    -Credential $cred `
    -OutputCSV "C:\RemoteHostInfo-$(Get-Date -Format 'yyyyMMdd').csv" `
    -LogFile "C:\Get-RemoteHostInfo-$(Get-Date -Format 'yyyyMMdd').log" `
    -MaxConcurrency 150 `
    -TimeoutSeconds 45 `
    -MaxRetries 2
```

## 📝 参数说明

| 参数 | 类型 | 必需 | 默认值 | 说明 |
|------|------|------|--------|------|
| `ComputerListFile` | String | 是 | - | 包含计算机名称列表的文本文件路径（每行一个） |
| `Credential` | PSCredential | 否 | 当前用户 | 用于连接远程计算机的凭据 |
| `OutputCSV` | String | 否 | 自动生成 | 输出CSV文件路径（带时间戳） |
| `LogFile` | String | 否 | 自动生成 | 日志文件路径（带时间戳） |
| `MaxConcurrency` | Int | 否 | 100 | 最大并行处理数量（范围：1-200） |
| `TimeoutSeconds` | Int | 否 | 30 | 单个主机查询超时时间（秒，范围：5-300） |
| `MaxRetries` | Int | 否 | 2 | 失败重试次数（范围：0-5） |

## 📊 输出格式

### CSV文件格式

导出的CSV文件包含以下列：

| 列名 | 说明 | 示例 |
|------|------|------|
| `ComputerName` | 计算机名 | SERVER01 |
| `IPAddress` | IP地址 | 192.168.1.100 |
| `MACAddress` | MAC地址 | AA-BB-CC-DD-EE-FF |
| `Status` | 查询状态 | 成功/失败 |
| `ErrorMessage` | 错误信息 | （成功时为空） |
| `QueryTimeSeconds` | 查询耗时（秒） | 2.35 |

### CSV示例

```csv
ComputerName,IPAddress,MACAddress,Status,ErrorMessage,QueryTimeSeconds
SERVER01,192.168.1.100,AA-BB-CC-DD-EE-FF,成功,,2.35
SERVER02,192.168.1.101,11-22-33-44-55-66,成功,,1.89
SERVER03,,,失败,WinRM连接失败: 无法连接到远程服务器,5.12
```

### 日志文件格式

日志文件包含详细的操作记录，格式如下：

```
[2025-12-01 10:30:15.123] [TID:1] [INFO] 远程主机信息查询脚本开始执行
[2025-12-01 10:30:15.125] [TID:1] [INFO] 计算机列表文件: C:\computers.txt
[2025-12-01 10:30:15.200] [TID:1] [SUCCESS] 成功读取 10 台计算机
[2025-12-01 10:30:15.250] [TID:5] [PROGRESS] [进度: 1/10 (10.0%)] SERVER01 - 成功
[2025-12-01 10:30:16.100] [TID:6] [ERROR] SERVER02 - WinRM连接失败: 无法连接到远程服务器
```

日志级别说明：
- **INFO**：一般信息
- **SUCCESS**：成功操作
- **ERROR**：错误信息
- **WARNING**：警告信息
- **PROGRESS**：进度信息
- **DEBUG**：调试信息（不输出到控制台）

## 🔧 工作原理

### 查询流程

1. **读取计算机列表**：从文本文件读取计算机名称列表
2. **并行处理**：根据PowerShell版本选择并行处理方式
   - PowerShell 7+：使用 `ForEach-Object -Parallel`
   - PowerShell 5.1：使用 `Start-Job`
3. **连通性测试**：测试WinRM连接（带重试机制）
4. **远程查询**：在远程主机上执行脚本块，获取系统信息
5. **结果收集**：收集所有查询结果
6. **CSV导出**：将结果导出为CSV文件

### 信息获取方式

脚本在远程主机上执行以下操作：

1. **计算机名**：
   - 优先使用 `$env:COMPUTERNAME`
   - 备用：`Get-CimInstance Win32_ComputerSystem`

2. **IP地址和MAC地址**：
   - 优先使用 `Get-NetAdapter` + `Get-NetIPAddress`（Windows 8/Server 2012+）
   - 兼容使用 `Get-CimInstance Win32_NetworkAdapterConfiguration`（Windows Server 2012 R2）
   - 过滤条件：
     - 状态为"Up"
     - 非虚拟网卡
     - 排除Loopback、Teredo、isatap等
     - 获取第一个活动网卡的信息

3. **MAC地址格式化**：
   - 自动格式化为标准格式：`AA-BB-CC-DD-EE-FF`

## ⚠️ 注意事项

1. **WinRM配置**：确保目标计算机已启用WinRM服务
2. **防火墙规则**：确保防火墙允许WinRM连接（端口5985/5986）
3. **权限要求**：需要适当的权限才能连接远程计算机
4. **网络连通性**：确保能够通过网络访问目标计算机
5. **PowerShell版本**：建议使用PowerShell 5.1或更高版本
6. **并发数量**：根据网络和系统性能调整 `MaxConcurrency` 参数
7. **超时设置**：根据网络延迟情况调整 `TimeoutSeconds` 参数

## 🐛 故障排查

### 常见问题

#### 1. WinRM连接失败

**错误信息**：
```
WinRM连接失败: 无法连接到远程服务器
```

**解决方案**：
- 检查目标计算机是否启用WinRM服务：`Get-Service WinRM`
- 检查防火墙规则是否允许WinRM连接
- 检查网络连通性：`Test-NetConnection -ComputerName SERVER01 -Port 5985`
- 在目标计算机上运行：`Enable-PSRemoting -Force`

#### 2. 权限不足

**错误信息**：
```
查询失败: 访问被拒绝
```

**解决方案**：
- 使用具有管理员权限的账户
- 使用 `-Credential` 参数提供正确的凭据
- 检查目标计算机的本地安全策略

#### 3. 超时错误

**错误信息**：
```
查询失败: 操作超时
```

**解决方案**：
- 增加 `-TimeoutSeconds` 参数值
- 检查网络延迟情况
- 检查目标计算机性能

#### 4. 找不到网络适配器

**错误信息**：
```
获取网络信息失败: 未找到活动的网络适配器
```

**解决方案**：
- 检查目标计算机是否有活动的网络连接
- 检查网络适配器是否已启用
- 检查是否有有效的IP地址配置

#### 5. 并行处理性能问题

**问题**：处理速度慢或系统资源占用高

**解决方案**：
- 降低 `-MaxConcurrency` 参数值
- 检查网络带宽
- 检查系统资源（CPU、内存）

### 调试技巧

1. **查看详细日志**：检查日志文件中的详细错误信息
2. **单独测试**：先测试单个计算机的连接
3. **网络诊断**：使用 `Test-NetConnection` 测试网络连通性
4. **WinRM诊断**：使用 `Test-WSMan` 测试WinRM连接

## 📈 性能优化建议

1. **并发数量**：根据网络和系统性能调整 `MaxConcurrency`
   - 局域网环境：建议50-150（默认100）
   - 广域网环境：建议20-50
   - 高延迟网络：建议10-30

2. **超时设置**：根据网络延迟调整 `TimeoutSeconds`
   - 局域网：30秒
   - 广域网：60-90秒
   - 高延迟网络：120秒

3. **重试次数**：根据网络稳定性调整 `MaxRetries`
   - 稳定网络：1-2次
   - 不稳定网络：3-5次

## 📚 相关资源

- [PowerShell远程管理文档](https://docs.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote)
- [WinRM配置指南](https://docs.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)
- [项目GitHub仓库](https://github.com/iamtornado/common_powershell_scripts)

## 📄 许可证

[MIT](LICENSE)

## 👤 作者信息

- **作者**：tornadoami
- **微信公众号**：AI发烧友
- **DreamAI官网**：[DreamAI官方网站](https://alidocs.dingtalk.com/i/nodes/Amq4vjg890AlRbA6Td9ZvlpDJ3kdP0wQ?utm_scene=team_space)
- **GitHub**：[iamtornado](https://github.com/iamtornado)

## 🔄 更新日志

### v1.0 (2025-12-01)
- 初始版本发布
- 支持批量查询远程主机信息
- 支持并行处理
- 完善的错误处理和日志记录
- CSV导出功能

