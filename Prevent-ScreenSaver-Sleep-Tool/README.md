# Prevent-ScreenSaver-Sleep-Tool

## 概述

这是一个专业的PowerShell脚本，使用Windows API (SetThreadExecutionState) 来防止计算机息屏、进入屏保和睡眠状态。该工具适用于长时间演示、自动化测试、远程监控等场景，支持多种运行模式和定时恢复功能。

## 功能特性

### ✅ 核心功能
- **防止息屏**：保持显示器常亮，防止屏幕自动关闭
- **防止睡眠**：防止系统进入睡眠状态
- **防止屏保**：绕过屏保策略，阻止屏保启动
- **定时恢复**：支持设置自动恢复时间
- **状态监控**：实时显示当前防屏保/睡眠状态

### ✅ 运行模式
- **DisplayOnly**：仅防止息屏，允许系统睡眠
- **SystemOnly**：仅防止睡眠，允许屏幕关闭
- **Both**：防止息屏和睡眠（默认模式）
- **None**：恢复正常状态

### ✅ 用户体验
- **彩色输出**：使用不同颜色区分信息类型
- **详细日志**：记录所有操作步骤
- **状态显示**：实时显示当前执行状态
- **帮助信息**：内置详细的使用说明

## 系统要求

### 最低要求
- **PowerShell**: 5.1 或更高版本
- **Windows**: Windows 7 或更高版本
- **权限**: 无需管理员权限（普通用户即可运行）

### 兼容性
- ✅ Windows 7/8/8.1/10/11
- ✅ PowerShell 5.1/6/7
- ✅ 域环境和非域环境

## 使用方法

### 基本用法

```powershell
# 防止息屏和睡眠（默认模式，无限期运行）
.\Prevent-ScreenSaver-Sleep-Tool.ps1

# 防止息屏和睡眠，持续2小时
.\Prevent-ScreenSaver-Sleep-Tool.ps1 -Mode Both -Duration 120

# 仅防止息屏，持续1小时
.\Prevent-ScreenSaver-Sleep-Tool.ps1 -Mode DisplayOnly -Duration 60

# 仅防止睡眠，持续30分钟
.\Prevent-ScreenSaver-Sleep-Tool.ps1 -Mode SystemOnly -Duration 30

# 恢复正常状态
.\Prevent-ScreenSaver-Sleep-Tool.ps1 -Mode None

# 显示当前状态
.\Prevent-ScreenSaver-Sleep-Tool.ps1 -ShowStatus

# 强制执行，跳过确认提示
.\Prevent-ScreenSaver-Sleep-Tool.ps1 -Mode Both -Duration 60 -Force
```

### 参数说明

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `Mode` | string | 否 | 运行模式：DisplayOnly, SystemOnly, Both, None |
| `Duration` | int | 否 | 持续时间（分钟），0表示无限期运行 |
| `ShowStatus` | switch | 否 | 显示当前状态信息 |
| `Force` | switch | 否 | 强制执行，跳过确认提示 |
| `WhatIf` | switch | 否 | 显示将要执行的操作，但不实际执行 |

## 实际应用场景

### 🎯 演示和培训
```powershell
# 演示期间防止息屏和睡眠
.\Prevent-ScreenSaver-Sleep-Tool.ps1 -Mode Both -Duration 180
```

### 🎯 自动化测试
```powershell
# 测试期间保持系统活跃
.\Prevent-ScreenSaver-Sleep-Tool.ps1 -Mode Both -Duration 480
```

### 🎯 远程监控
```powershell
# 远程监控期间防止系统睡眠
.\Prevent-ScreenSaver-Sleep-Tool.ps1 -Mode SystemOnly -Duration 0
```

### 🎯 长时间下载
```powershell
# 下载期间防止息屏
.\Prevent-ScreenSaver-Sleep-Tool.ps1 -Mode DisplayOnly -Duration 120
```

## 技术原理

### 🔧 Windows API调用
脚本使用 `SetThreadExecutionState` API 来控制系统的执行状态：

```csharp
// API常量定义
ES_CONTINUOUS = 0x80000000;        // 连续模式
ES_SYSTEM_REQUIRED = 0x00000001;    // 系统要求（防止睡眠）
ES_DISPLAY_REQUIRED = 0x00000002;   // 显示要求（防止息屏）
ES_AWAYMODE_REQUIRED = 0x00000040;  // 离开模式
```

### 🎯 模式说明

| 模式 | API标志 | 功能描述 |
|------|---------|----------|
| DisplayOnly | ES_CONTINUOUS \| ES_DISPLAY_REQUIRED | 仅防止息屏，允许系统睡眠 |
| SystemOnly | ES_CONTINUOUS \| ES_SYSTEM_REQUIRED | 仅防止睡眠，允许屏幕关闭 |
| Both | ES_CONTINUOUS \| ES_SYSTEM_REQUIRED \| ES_DISPLAY_REQUIRED | 防止息屏和睡眠 |
| None | ES_CONTINUOUS | 恢复正常状态 |

### 🛡️ 安全机制
- **无需管理员权限**：使用用户级API调用
- **自动恢复**：支持定时自动恢复正常状态
- **状态监控**：实时显示当前执行状态
- **错误处理**：完善的异常处理机制

## 输出示例

### 正常执行输出
```
╔══════════════════════════════════════════════════════════════╗
║              防止计算机息屏和睡眠工具                      ║
║         Prevent Screen Saver and Sleep Tool               ║
╚══════════════════════════════════════════════════════════════╝

脚本开始时间: 2025-07-31 14:30:00
运行模式: Both
持续时间: 120 分钟

正在加载Windows API...
✓ Windows API加载成功

即将执行的操作:
  模式: Both
  持续时间: 120 分钟
  结束时间: 2025-07-31 16:30:00

确认执行此操作？(Y/N): Y
正在设置：防止息屏和睡眠
✓ 执行状态设置成功

╔══════════════════════════════════════════════════════════════╗
║                        操作成功完成                          ║
╚══════════════════════════════════════════════════════════════╝

定时器已启动，将在 120 分钟后自动恢复正常状态...
后台作业已启动，作业ID: 1
要手动停止，请运行: Stop-Job -Id 1

╔══════════════════════════════════════════════════════════════╗
║                        当前状态信息                        ║
╚══════════════════════════════════════════════════════════════╝
当前执行状态: 0x80000003
状态详情:
  - 连续模式: 启用
  - 系统要求: 启用
  - 显示要求: 启用
  - 离开模式: 禁用
✓ 防屏保/睡眠功能已启用
```

### 状态查询输出
```
╔══════════════════════════════════════════════════════════════╗
║                        当前状态信息                        ║
╚══════════════════════════════════════════════════════════════╝
当前执行状态: 0x80000003
状态详情:
  - 连续模式: 启用
  - 系统要求: 启用
  - 显示要求: 启用
  - 离开模式: 禁用
✓ 防屏保/睡眠功能已启用
```

## 故障排除

### 常见问题

#### 1. "无法加载Windows API"错误
**原因**: PowerShell执行策略限制或系统兼容性问题
**解决**: 
- 检查执行策略：`Get-ExecutionPolicy`
- 临时允许脚本运行：`Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

#### 2. 脚本运行后仍然息屏
**原因**: 系统电源设置优先级更高
**解决**: 
- 检查系统电源设置
- 确认脚本状态：`.\Prevent-ScreenSaver-Sleep-Tool.ps1 -ShowStatus`

#### 3. 定时器不工作
**原因**: 后台作业被终止或系统重启
**解决**: 
- 检查后台作业状态：`Get-Job`
- 手动恢复正常：`.\Prevent-ScreenSaver-Sleep-Tool.ps1 -Mode None`

#### 4. 在域环境中被阻止
**原因**: 企业安全策略限制
**解决**: 
- 联系IT管理员确认策略
- 使用企业批准的替代方案

### 调试技巧

1. **启用详细输出**: 使用 `-Verbose` 参数
2. **检查状态**: 使用 `-ShowStatus` 参数
3. **预览操作**: 使用 `-WhatIf` 参数
4. **查看作业**: 使用 `Get-Job` 查看后台作业

## 常见问题解答 (FAQ)

### ❓ 脚本是否需要管理员权限？

**答**：不需要。脚本使用用户级API调用，普通用户即可运行。

### ❓ 脚本对系统性能有影响吗？

**答**：几乎没有影响。API调用非常轻量，不会占用系统资源。

### ❓ 脚本停止后会自动恢复正常吗？

**答**：是的。脚本停止或系统重启后会自动恢复正常状态。

### ❓ 可以同时运行多个实例吗？

**答**：可以，但建议只运行一个实例，避免冲突。

### ❓ 脚本支持远程计算机吗？

**答**：当前版本仅支持本地计算机，远程功能需要额外开发。

### ❓ 如何手动停止防屏保功能？

**答**：运行 `.\Prevent-ScreenSaver-Sleep-Tool.ps1 -Mode None`

### ❓ 脚本是否会影响其他应用程序？

**答**：不会。脚本只影响系统级电源管理，不影响应用程序运行。

### ❓ 在企业环境中使用需要注意什么？

**答**：
- 确认企业安全策略允许
- 避免违反合规要求
- 建议与IT部门沟通

## 版本历史

### v1.0 (2025-07-31)
- ✅ 初始版本发布
- ✅ 实现基本的防屏保和防睡眠功能
- ✅ 支持多种运行模式
- ✅ 添加定时恢复功能
- ✅ 实现状态监控和显示
- ✅ 添加详细的错误处理机制
- ✅ 支持后台作业和定时器

## 文件结构

```
Prevent-ScreenSaver-Sleep-Tool/
├── Prevent-ScreenSaver-Sleep-Tool.ps1    # 主脚本文件
├── README.md                              # 说明文档
└── .gitignore                             # Git忽略文件配置
```

## 技术支持

### 问题报告
如果遇到问题，请提供以下信息：
1. PowerShell版本 (`$PSVersionTable.PSVersion`)
2. Windows版本 (`[System.Environment]::OSVersion`)
3. 错误信息和完整的执行日志
4. 执行策略设置 (`Get-ExecutionPolicy`)

### 贡献
欢迎提交改进建议和问题报告！

## 许可证

此工具仅供内部使用，请遵守相关安全策略和合规要求。

---

**注意**: 此脚本使用Windows API调用，确保PowerShell执行策略允许运行脚本。 