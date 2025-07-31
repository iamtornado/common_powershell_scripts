# 通过ADSI查询远程Windows计算机管理员组成员

## 📖 脚本简介

本脚本使用 **ADSI (Active Directory Service Interfaces)** 技术连接到指定的远程Windows计算机，查询并列出该计算机上本地 `Administrators` 组的所有成员信息。相比传统的WMI或PowerShell远程管理方式，ADSI提供了更直接的本地用户和组访问方法。

## ✨ 主要功能

- 🔍 **远程查询**：通过ADSI连接远程计算机，无需启用PowerShell远程管理
- 👥 **成员详情**：显示管理员组成员的名称、类型、来源和ADsPath信息
- 🛡️ **来源识别**：自动区分本地账户和域账户来源
- 🔧 **错误处理**：完善的异常处理机制，提供详细的错误诊断信息
- 📶 **连通性检查**：执行前先进行网络连通性测试

## 📋 脚本信息

| 项目 | 详情 |
|------|------|
| **脚本名称** | Get-RemoteAdminMembers_ADSI.ps1 |
| **版本** | 1.0 |
| **适用系统** | Windows PowerShell 5.0+ / PowerShell Core 6.0+ |
| **权限要求** | 需要对目标计算机的管理访问权限 |
| **网络要求** | 目标计算机135端口(DCOM)可达 |

## 🚀 使用方法

### 基本语法
```powershell
.\Get-RemoteAdminMembers_ADSI.ps1 -ComputerName <计算机名或IP地址>
```

### 使用示例

#### 示例1：查询域内计算机
```powershell
.\Get-RemoteAdminMembers_ADSI.ps1 -ComputerName "WIN-SERVER01"
```

#### 示例2：通过IP地址查询
```powershell
.\Get-RemoteAdminMembers_ADSI.ps1 -ComputerName "192.168.1.100"
```

#### 示例3：查询工作组计算机
```powershell
.\Get-RemoteAdminMembers_ADSI.ps1 -ComputerName "WORKGROUP-PC"
```

## 📊 输出示例

脚本成功执行后，将显示类似以下格式的输出：

```
正在通过 ADSI 查询远程计算机 'WIN-SERVER01' 上的本地 Administrators 组成员...
成功连接到远程计算机 'WIN-SERVER01' 上的 Administrators 组对象。

远程计算机 'WIN-SERVER01' 上的 Administrators 组成员：

Name                Type PrincipalSource        ADsPath
----                ---- ---------------        -------
Administrator       User Local                 WinNT://WIN-SERVER01/Administrator
Domain Admins       Group Domain (CONTOSO)     WinNT://CONTOSO/Domain Admins
CONTOSO\john.doe    User Domain (CONTOSO)      WinNT://CONTOSO/john.doe
Backup Operators    Group Local                WinNT://WIN-SERVER01/Backup Operators

脚本执行完毕。
```

## ⚙️ 参数说明

### ComputerName (必需)
- **类型**：String
- **说明**：要查询的远程Windows计算机名称或IP地址
- **示例**：`"WIN-SERVER01"`, `"192.168.1.100"`

## 🔧 技术原理

### ADSI工作机制
1. **连接建立**：通过 `WinNT://` 提供程序建立到远程计算机的ADSI连接
2. **组对象获取**：访问目标计算机的 `Administrators` 组对象
3. **成员枚举**：遍历组内所有成员，获取详细属性信息
4. **来源解析**：根据ADsPath分析成员来源（本地/域）

### 网络协议要求
- **DCOM**：使用分布式组件对象模型进行远程访问
- **端口**：主要使用TCP 135端口和动态RPC端口
- **认证**：基于当前用户凭据或显式指定的凭据

## ⚠️ 注意事项

### 权限要求
- 运行脚本的用户必须对目标计算机具有**管理员权限**
- 在域环境中，建议使用域管理员账户
- 工作组环境中需要目标计算机的本地管理员凭据

### 网络配置
- 确保防火墙允许DCOM流量（TCP 135 + 动态端口）
- 在高安全性环境中可能需要配置DCOM安全设置
- 建议在可信网络环境中使用

### 兼容性说明
- ✅ 支持Windows Server 2008 R2及更高版本
- ✅ 支持Windows 7/8/10/11客户端系统
- ✅ 同时适用于域环境和工作组环境
- ⚠️ 某些受限环境可能需要额外的安全配置

## 🔍 故障排除

### 常见错误及解决方案

#### 1. "访问被拒绝"错误
**原因**：权限不足或认证失败
**解决方案**：
- 使用管理员身份运行PowerShell
- 确认对目标计算机具有管理权限
- 检查UAC设置是否影响远程访问

#### 2. "无法连接到远程计算机"错误
**原因**：网络不通或目标计算机不可达
**解决方案**：
- 检查网络连通性：`ping <ComputerName>`
- 验证计算机名/IP地址是否正确
- 确认目标计算机在线且响应网络请求

#### 3. DCOM连接失败
**原因**：防火墙阻止或DCOM配置问题
**解决方案**：
- 检查Windows防火墙设置
- 验证DCOM服务运行状态
- 考虑临时禁用防火墙进行测试

## 📝 更新日志

### Version 1.0 (2025-07-31)
- ✨ 初始版本发布
- 🔍 实现基于ADSI的远程管理员组查询功能
- 🛡️ 添加完善的错误处理和诊断信息
- 📊 支持成员来源识别（本地/域）
- 📶 集成网络连通性检查功能

## 🤝 反馈与贡献

如果您在使用过程中遇到问题或有改进建议，欢迎：
- 📧 发送邮件至：1426693102@qq.com
- 🐛 提交Issue或Pull Request
- 💬 关注微信公众号"AI发烧友"获取更多技術分享

## 📄 许可证

本脚本遵循 [MIT许可证](../LICENSE) 开源发布。