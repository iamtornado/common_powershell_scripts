# 系统信息查询工具 📊

> **System Information Query Tool**  
> 支持本地和远程Windows计算机系统信息查询的PowerShell工具

## 📋 功能概述

这是一个专为IT运维和技术支持设计的PowerShell脚本，能够快速收集本地或远程Windows计算机的关键系统信息，并自动复制到剪切板，方便用户直接发送给IT工程师进行故障诊断和技术支持。

### ✨ 主要特性

- 🖥️ **本地/远程查询**：支持本地计算机和远程Windows计算机信息查询
- 🔗 **智能连接**：自动选择最佳远程连接方式（WinRM优先，DCOM/WMI备用）
- 🌐 **网络配置**：智能检测所有活动网卡（包括虚拟网卡）的IP和MAC地址
- 💾 **系统详情**：操作系统版本、架构、制造商、型号、内存信息
- 🔐 **凭据支持**：支持使用自定义凭据连接远程计算机
- 📋 **自动复制**：结果自动复制到剪切板，可直接粘贴发送
- 💾 **文件保存**：支持将信息保存到文本文件
- 🎨 **友好界面**：彩色输出，详细的连接状态和错误提示

## 🚀 快速开始

### 本地查询

```powershell
# 查询本地计算机信息
.\Get-SystemInfo.ps1

# 查询本地信息并保存到文件
.\Get-SystemInfo.ps1 -SaveToFile -OutputPath "LocalInfo.txt"
```

### 远程查询

```powershell
# 查询远程计算机（使用当前用户凭据）
.\Get-SystemInfo.ps1 -ComputerName "SERVER01"

# 使用IP地址查询远程计算机
.\Get-SystemInfo.ps1 -ComputerName "192.168.1.100"

# 使用指定凭据查询远程计算机
$cred = Get-Credential
.\Get-SystemInfo.ps1 -ComputerName "SERVER01.domain.com" -Credential $cred

# 远程查询并保存到文件
.\Get-SystemInfo.ps1 -ComputerName "SERVER01" -SaveToFile -OutputPath "Server01_Info.txt"
```

## 📝 输出示例

### 本地查询示例

```
=================================
    系统信息查询工具
  System Information Tool
=================================

开始本地系统信息查询...
正在获取计算机信息...
正在获取用户信息...
正在获取网络信息...
正在获取系统详细信息...

计算机名 (FQDN): PC001.company.com
当前登录用户: COMPANY\john.doe

网卡 1 - 以太网 (物理网卡)
  IP地址: 192.168.1.100
  MAC地址: AA-BB-CC-DD-EE-FF

网卡 2 - vEthernet (external) (虚拟网卡)
  IP地址: 192.168.124.11
  MAC地址: 00-15-5D-7C-0B-00

操作系统: Microsoft Windows 11 专业版
系统版本: 10.0.22631
系统架构: 64-bit
制造商: Dell Inc.
型号: OptiPlex 7090
总内存: 16.00 GB

=================================

✅ 详细信息已自动复制到剪切板！
请直接在IM软件（如钉钉、企业微信、飞书等）中粘贴发送给IT工程师
```

### 远程查询示例

```
=================================
    系统信息查询工具
  System Information Tool
  远程目标: SERVER01.company.com
=================================

开始远程系统信息查询...
正在检测网络连通性...
✓ 网络连通性检测成功
正在测试WinRM连接...
✓ WinRM连接测试成功
✓ 使用WinRM连接方式
正在通过WinRM获取远程系统信息...

计算机名 (FQDN): SERVER01
当前登录用户: COMPANY\admin

网卡 1 - 以太网 (物理网卡)
  IP地址: 192.168.1.50
  MAC地址: 00-50-56-C0-00-01

操作系统: Microsoft Windows Server 2022 Standard
系统版本: 10.0.20348
系统架构: 64-bit
制造商: VMware, Inc.
型号: VMware Virtual Platform
总内存: 8.00 GB

=================================

✅ 详细信息已自动复制到剪切板！
远程计算机: SERVER01.company.com
连接方式: WinRM
请直接在IM软件（如钉钉、企业微信、飞书等）中粘贴发送给IT工程师
```

## 🔧 参数说明

| 参数 | 类型 | 说明 | 默认值 |
|------|------|------|--------|
| `-ComputerName` | String | 目标计算机名称或IP地址，留空则查询本地计算机 | `""` |
| `-Credential` | PSCredential | 用于连接远程计算机的凭据 | `$null` |
| `-SaveToFile` | Switch | 是否保存信息到文件 | `$false` |
| `-OutputPath` | String | 输出文件路径 | `"SystemInfo.txt"` |
| `-Force` | Switch | 强制执行，跳过确认提示 | `$false` |
| `-Timeout` | Int | 远程连接超时时间（秒） | `30` |

## 🔗 远程连接说明

### 连接方式优先级

脚本会自动测试并选择最佳的远程连接方式：

1. **WinRM (Windows Remote Management)** - 优先选择
   - 现代化的远程管理协议
   - 更好的安全性和性能
   - 支持完整的PowerShell远程功能

2. **DCOM/WMI (Distributed COM)** - 备用方案
   - 传统的Windows远程管理方式
   - 兼容性更好，适用于旧版本系统
   - 部分功能可能受限

### 连接测试流程

```
网络连通性测试 → WinRM连接测试 → WMI连接测试 → 选择可用方式
     ↓               ↓               ↓
   PING测试      Test-WSMan      WMI查询测试
```

## 🌐 网络检测说明

脚本能够智能检测各种网络适配器：

### ✅ 支持的网卡类型
- 物理以太网卡
- 无线网卡
- Hyper-V虚拟网卡
- VMware虚拟网卡
- Docker网络适配器

### ❌ 自动过滤的网卡
- 回环适配器 (Loopback)
- Teredo隧道适配器
- ISATAP适配器
- 蓝牙网络适配器

## 💼 适用场景

### 🎯 IT运维支持
- **远程技术支持**：快速获取用户电脑或服务器信息
- **故障诊断**：收集系统信息进行问题分析
- **资产管理**：批量收集设备硬件和软件信息
- **网络监控**：检查远程设备的网络配置状态

### 👥 最终用户
- **问题报告**：向IT部门提供详细的系统信息
- **兼容性检查**：软件安装前的系统环境验证
- **网络排查**：诊断本地网络连接问题

### 🏢 企业环境
- **标准化流程**：统一的系统信息收集标准
- **批量管理**：同时查询多台计算机的信息
- **合规审计**：定期收集系统配置信息
- **远程运维**：无需物理接触即可获取设备信息

## ⚙️ 系统要求

### 本地查询
- **操作系统**：Windows 7 及以上版本
- **PowerShell**：5.1 及以上版本
- **权限**：普通用户权限即可

### 远程查询
- **目标系统**：Windows 7/Server 2008 及以上版本
- **网络连接**：能够访问目标计算机
- **权限要求**：目标计算机的管理员权限
- **服务要求**：
  - **WinRM方式**：目标计算机启用WinRM服务
  - **WMI方式**：目标计算机启用WMI和DCOM服务

### 防火墙端口
- **WinRM**：TCP 5985 (HTTP) 或 5986 (HTTPS)
- **WMI/DCOM**：TCP 135 + 动态端口范围

## 🔍 技术实现

### 核心技术栈
- **PowerShell Remoting**：WinRM远程执行
- **PowerShell CIM/WMI**：系统信息获取
- **Net-* Cmdlets**：网络配置查询
- **System.Net.Dns**：FQDN解析
- **Set-Clipboard**：剪切板操作

### 关键特性
- **智能连接选择**：自动测试并选择最佳远程连接方式
- **智能网卡检测**：自动识别物理和虚拟网卡
- **凭据管理**：安全的远程认证处理
- **错误处理**：完善的异常捕获和处理
- **编码支持**：正确显示中文字符
- **跨版本兼容**：支持不同Windows版本

## 📁 文件结构

```
系统信息查询工具/
├── Get-SystemInfo.ps1    # 主脚本文件（支持本地/远程查询）
├── Test-Clipboard.ps1    # 剪切板测试工具
└── README.md            # 本文档
```

## 🐛 故障排除

### 本地查询问题

**Q: 显示"未找到活动的网络连接"**  
A: 这通常是因为网卡驱动问题或网络配置异常，脚本会尝试检测所有可用的网络适配器。

**Q: 剪切板复制失败**  
A: 可能是PowerShell版本较低或系统权限限制，可以使用 `-SaveToFile` 参数保存到文件。

**Q: 中文显示乱码**  
A: 脚本已设置UTF-8编码，如仍有问题请检查PowerShell控制台编码设置。

### 远程查询问题

**Q: "无法连接到远程计算机"**  
A: 检查网络连通性、防火墙设置和目标计算机是否在线。

**Q: "WinRM连接测试失败"**  
A: 目标计算机可能未启用WinRM服务，可尝试以下命令启用：
```powershell
# 在目标计算机上执行
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

**Q: "WMI连接测试失败"**  
A: 检查WMI服务状态和DCOM配置，确保防火墙允许WMI通信。

**Q: "用户权限不足或凭据无效"**  
A: 确保使用的凭据具有目标计算机的管理员权限。

**Q: 远程查询速度慢**  
A: WMI方式通常比WinRM慢，建议优先配置WinRM服务。

### 测试工具

使用附带的测试脚本验证剪切板功能：

```powershell
.\Test-Clipboard.ps1
```

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](../LICENSE) 文件

## 🤝 贡献指南

欢迎提交Issue和Pull Request来改进这个工具！

### 开发规范
- 遵循PowerShell最佳实践
- 添加适当的错误处理
- 保持代码注释完整
- 确保跨版本兼容性

## 📞 技术支持

如有问题或建议，请通过以下方式联系：

- 📧 Email: [您的邮箱]
- 🐛 Issues: [GitHub Issues链接]
- 💬 讨论: [GitHub Discussions链接]

---

**版本**: 2.0  
**最后更新**: 2025-07-31  
**作者**: tornadoami

## 📈 版本历史

### v2.0 (2025-07-31)
- ✨ 新增远程计算机查询功能
- 🔗 支持WinRM和WMI两种连接方式
- 🔐 添加凭据认证支持
- 🎯 智能连接方式选择
- 📊 增强错误处理和状态显示
- 📝 完善文档和使用示例

### v1.0 (2025-07-31)
- 🎉 首次发布
- 🖥️ 本地系统信息查询
- 🌐 网络适配器智能检测
- 📋 自动剪切板复制
- 💾 文件保存功能