# Export-ADGroupMembers

查询活动目录(AD)中指定组的成员信息，并导出为 CSV 文件。

## 功能

- 根据提供的组名列表，递归查询每个组下的**用户**成员（含嵌套组中的用户）
- 导出字段至少包含：**用户名（工号）**、**姓名**、**OU**
- 额外包含：组名、SamAccountName、UserPrincipalName、DistinguishedName
- 工号优先取 AD 属性 `EmployeeNumber`，其次 `EmployeeID`，若无则使用 `SamAccountName`

## 环境要求

- Windows PowerShell 5.1 或 **PowerShell 7 (Core)** 均可
- **Active Directory** PowerShell 模块（通常随 RSAT 或域控制器安装）
- 域内账号具备查询组及用户属性的权限

导出 CSV 使用 **UTF-8 带 BOM**、**Windows 换行符 (CRLF)**，在 PowerShell 7 下也能正确生成多行文件，复制到本机或 Excel 打开无异常。

## 用法

### 1. 使用内置测试组列表（直接运行）

脚本默认已包含你提供的测试组列表，直接运行即可：

```powershell
.\Export-ADGroupMembers.ps1
```

导出文件默认保存在当前目录，文件名形如：`ADGroupMembers_20250312_143022.csv`。

### 2. 指定组名和输出路径

```powershell
.\Export-ADGroupMembers.ps1 -GroupNames "g.test.admin","g.test.all" -OutputPath "D:\Report\members.csv"
```

### 3. 从文件读取组名（推荐：无管道绑定报错）

```powershell
.\Export-ADGroupMembers.ps1 -GroupFile "d:\groups.txt" -OutputPath "members.csv"
```

或把文件内容作为参数传入：

```powershell
.\Export-ADGroupMembers.ps1 -GroupNames (Get-Content d:\groups.txt) -OutputPath "members.csv"
```

### 4. 指定域控制器或凭据

```powershell
.\Export-ADGroupMembers.ps1 -GroupNames "g.test.admin" -Server "dc01.contoso.com" -Credential (Get-Credential)
```

### 5. 调试模式（排查“只导出一个组”“CSV 只显示一行”等）

加上 `-DebugMode` 会在控制台输出组列表来源、每组处理顺序、本组添加行数、累计行数、导出前不同组数等，并在 CSV 同目录生成 `输出文件名.debug.log`。写入后会校验文件行数，便于确认是否打开了正确文件。

```powershell
.\Export-ADGroupMembers.ps1 -GroupFile "d:\groups.txt" -OutputPath "members.csv" -DebugMode
```

## CSV 列说明

| 列名 | 说明 |
|------|------|
| 组名 | 该成员所属的 AD 组名 |
| 用户名(工号) | 工号优先取 EmployeeNumber/EmployeeID，否则为 SamAccountName |
| SamAccountName | AD 登录名 |
| 姓名 | DisplayName |
| OU | 用户所在 OU 路径（如 IT/Users） |
| UserPrincipalName | UPN |
| DistinguishedName | 用户完整 DN |

同一用户若属于多个组，会在 CSV 中出现多行（每行对应一个组）。  
若 Excel 直接打开仍乱码，可用 **数据 → 从文本/CSV** 导入，编码选择 **UTF-8**。

## 测试组列表（脚本默认）

- g.mybox.cmsuser, g.mybox.scadauser, g.mybox.yunweiuser, g.mybox.zhukonguser  
- g.myboxuser, g.mybox.admin, g.mybox.cmsedit, g.mybox.cmsrw  
- g.offshore.admin, g.offshore.all, g.offshore.cmsedit, g.offshore.jzuser  
- g.offshore.scadauser, g.offshore.zhukonguser  

若需只查询部分组，请使用 `-GroupNames` 参数覆盖默认列表。
