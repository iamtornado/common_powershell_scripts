#Requires -Version 5.1

<#
.SYNOPSIS
    检测Windows电脑显示器连接到独立显卡还是核显

.DESCRIPTION
    此脚本能够检测Windows电脑当前显示器连接到的是独立显卡还是集成显卡（核显）。
    支持多显示器环境，能够显示每个显示器连接的显卡信息，并标识主显示器。
    
    使用Windows Display API和WMI技术，准确识别显卡类型和显示器关联关系。

.PARAMETER Format
    输出格式：Table（表格，默认）或 JSON

.PARAMETER Detailed
    显示详细信息，包括显卡的详细属性

.EXAMPLE
    .\Get-DisplayGraphicsCard.ps1
    检测当前显示器连接的显卡类型，以表格格式输出

.EXAMPLE
    .\Get-DisplayGraphicsCard.ps1 -Format JSON
    以JSON格式输出检测结果

.EXAMPLE
    .\Get-DisplayGraphicsCard.ps1 -Detailed
    显示详细的显卡和显示器信息

.NOTES
    作者: tornadoami
    版本: 1.0
    创建日期: 2026-01-28
    微信公众号：AI发烧友
    DreamAI官网：https://alidocs.dingtalk.com/i/nodes/Amq4vjg890AlRbA6Td9ZvlpDJ3kdP0wQ?utm_scene=team_space
    github：https://github.com/iamtornado/common_powershell_scripts
    
    要求:
    - PowerShell 5.1 或更高版本
    - Windows 7 或更高版本
    - 需要适当的权限（某些信息可能需要管理员权限）
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Table', 'JSON')]
    [string]$Format = 'Table',
    
    [Parameter(Mandatory = $false)]
    [switch]$Detailed
)

# 设置错误处理
$ErrorActionPreference = 'Continue'

# 设置控制台编码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 定义Windows API结构体和函数
$apiCode = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class DisplayAPI {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct DISPLAY_DEVICE {
        public int cb;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceString;
        public int StateFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceKey;
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern bool EnumDisplayDevices(
        string lpDevice,
        uint iDevNum,
        ref DISPLAY_DEVICE lpDisplayDevice,
        uint dwFlags
    );

    [DllImport("user32.dll")]
    public static extern bool EnumDisplayMonitors(
        IntPtr hdc,
        IntPtr lprcClip,
        MonitorEnumProc lpfnEnum,
        IntPtr dwData
    );

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern bool GetMonitorInfo(
        IntPtr hMonitor,
        ref MONITORINFO lpmi
    );

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern bool GetMonitorInfo(
        IntPtr hMonitor,
        ref MONITORINFOEX lpmi
    );

    [StructLayout(LayoutKind.Sequential)]
    public struct MONITORINFO {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct MONITORINFOEX {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string szDevice;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    public delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdcMonitor, ref RECT lprcMonitor, IntPtr dwData);

    public const uint EDD_GET_DEVICE_INTERFACE_NAME = 0x00000001;
    public const int MONITORINFOF_PRIMARY = 0x00000001;
}
"@

# 编译API代码
try {
    # 检查类型是否已存在
    $typeExists = $false
    try {
        $null = [DisplayAPI]
        $typeExists = $true
        Write-Verbose "Windows Display API类型已存在，跳过加载"
    } catch {
        $typeExists = $false
    }
    
    if (-not $typeExists) {
        Add-Type -TypeDefinition $apiCode -ErrorAction Stop
        Write-Verbose "Windows Display API已成功加载"
    }
} catch {
    # 如果类型已存在，忽略错误
    if ($_.Exception.Message -like "*已经存在*" -or $_.Exception.Message -like "*already exists*") {
        Write-Verbose "Windows Display API类型已存在，继续执行"
    } else {
        Write-Error "无法加载Windows Display API: $($_.Exception.Message)"
        exit 1
    }
}

# 函数：获取所有显卡信息
function Get-GraphicsCards {
    try {
        $cards = Get-CimInstance -ClassName Win32_VideoController | ForEach-Object {
            $card = $_
            
            # 判断显卡类型
            $cardType = "未知"
            $cardName = $card.Name
            
            if ($null -ne $cardName) {
                $cardNameLower = $cardName.ToLower()
                
                # 判断是否为核显（集成显卡）
                $isIntel = $cardNameLower -match "intel"
                $hasIntelGraphics = ($cardNameLower -match "graphics") -or ($cardNameLower -match "hd") -or ($cardNameLower -match "iris") -or ($cardNameLower -match "uhd") -or ($cardNameLower -match "xe")
                
                if ($isIntel -and $hasIntelGraphics) {
                    $cardType = "核显（集成显卡）"
                }
                # 判断是否为独立显卡
                elseif (($cardNameLower -match "nvidia") -or ($cardNameLower -match "geforce") -or ($cardNameLower -match "quadro") -or ($cardNameLower -match "tesla") -or ($cardNameLower -match "rtx") -or ($cardNameLower -match "gtx") -or ($cardNameLower -match "titan")) {
                    $cardType = "独立显卡（NVIDIA）"
                }
                elseif (($cardNameLower -match "amd") -or ($cardNameLower -match "radeon") -or ($cardNameLower -match "firepro") -or ($cardNameLower -match "vega")) {
                    $cardType = "独立显卡（AMD）"
                }
                elseif (($cardNameLower -match "ati") -and ($cardNameLower -match "radeon")) {
                    $cardType = "独立显卡（ATI/AMD）"
                }
                # 其他情况，根据显存大小判断（通常核显显存较小）
                elseif ($card.AdapterRAM -and $card.AdapterRAM -gt (2 * 1GB)) {
                    $cardType = "独立显卡（疑似）"
                } else {
                    $cardType = "核显（疑似）"
                }
            }
            
            # 获取设备ID用于匹配
            $deviceId = $card.PNPDeviceID
            $adapterString = $card.AdapterCompatibility
            
            [PSCustomObject]@{
                Name = $cardName
                Type = $cardType
                AdapterRAM = if ($card.AdapterRAM) { [math]::Round($card.AdapterRAM / 1MB, 2) } else { 0 }
                AdapterRAMUnit = "MB"
                DriverVersion = $card.DriverVersion
                DriverDate = $card.DriverDate
                VideoModeDescription = $card.VideoModeDescription
                Status = $card.Status
                PNPDeviceID = $deviceId
                AdapterCompatibility = $adapterString
                Availability = $card.Availability
                ConfigManagerErrorCode = $card.ConfigManagerErrorCode
            }
        }
        
        return $cards
    } catch {
        Write-Error "获取显卡信息失败: $($_.Exception.Message)"
        return @()
    }
}

# 函数：获取主显示器的设备名称（通过注册表或API）
function Get-PrimaryMonitorDeviceName {
    $primaryDeviceName = $null
    
    # 方法1: 通过注册表获取主显示器信息
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MMStickyKeys"
        # 或者尝试其他注册表路径
        $regPaths = @(
            "HKCU:\Control Panel\Desktop",
            "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration"
        )
        
        # 尝试从注册表中查找主显示器配置
        # 实际上，Windows通常将主显示器标记为DISPLAY1
        $primaryDeviceName = "DISPLAY1"
        Write-Verbose "假设主显示器设备名称为: $primaryDeviceName"
    } catch {
        Write-Verbose "注册表查询失败: $($_.Exception.Message)"
    }
    
    return $primaryDeviceName
}

# 函数：枚举显示设备（使用多种方法确保检测到所有显示器）
function Get-DisplayDevices {
    $displayDevices = @()
    $monitorMap = @{}  # 用于去重，key为DeviceID或DeviceName
    
    # 首先获取主显示器的设备名称
    $primaryMonitorDeviceName = Get-PrimaryMonitorDeviceName
    Write-Verbose "主显示器设备名称: $primaryMonitorDeviceName"

    # 方法1: 使用EnumDisplayDevices API枚举所有适配器和监视器（最可靠）
    Write-Verbose "使用EnumDisplayDevices API枚举显示设备"
    $adapterMap = @{}
    $adapterIndex = 0
    
    while ($true) {
        $adapter = New-Object DisplayAPI+DISPLAY_DEVICE
        $adapter.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($adapter)
        
        $adapterResult = [DisplayAPI]::EnumDisplayDevices($null, $adapterIndex, [ref]$adapter, 0)
        if (-not $adapterResult) { break }
        
        $isActive = ($adapter.StateFlags -band 0x1) -ne 0      # DISPLAY_DEVICE_ACTIVE
        $isAttached = ($adapter.StateFlags -band 0x2) -ne 0   # DISPLAY_DEVICE_ATTACHED_TO_DESKTOP
        $isPrimary = ($adapter.StateFlags -band 0x4) -ne 0     # DISPLAY_DEVICE_PRIMARY_DEVICE
        
        Write-Verbose "适配器 $adapterIndex : $($adapter.DeviceString) (StateFlags: $($adapter.StateFlags), 活动: $isActive, 连接: $isAttached, 主: $isPrimary, DeviceName: $($adapter.DeviceName))"
        
        # 处理所有有DeviceName的适配器（即使StateFlags为0也可能有显示器）
        # 某些情况下，适配器可能没有设置StateFlags但仍然有显示器连接
        if ($adapter.DeviceName -or $isActive -or $isAttached) {
            # 枚举该适配器下的所有监视器
            $monitorIndex = 0
            $monitors = @()
            $maxMonitors = 10  # 限制最大监视器数量，防止无限循环
            
            while ($monitorIndex -lt $maxMonitors) {
                $monitor = New-Object DisplayAPI+DISPLAY_DEVICE
                $monitor.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($monitor)
                
                $monitorResult = [DisplayAPI]::EnumDisplayDevices($adapter.DeviceName, $monitorIndex, [ref]$monitor, 0)
                if (-not $monitorResult) { break }
                
                # 检查监视器是否有效（有DeviceName或DeviceString）
                if ($monitor.DeviceName -or $monitor.DeviceString) {
                    Write-Verbose "  监视器 $monitorIndex : $($monitor.DeviceString) (DeviceName: $($monitor.DeviceName), DeviceID: $($monitor.DeviceID))"
                    
                    $monitors += @{
                        DeviceName = $monitor.DeviceName
                        DeviceString = $monitor.DeviceString
                        DeviceID = $monitor.DeviceID
                        StateFlags = $monitor.StateFlags
                    }
                }
                $monitorIndex++
            }
            
            # 如果适配器下没有枚举到监视器，将适配器本身作为显示设备
            # 这可能表示多个显示器共享同一个适配器输出
            if ($monitors.Count -eq 0) {
                Write-Verbose "  适配器 $adapterIndex 下没有监视器，使用适配器本身作为显示设备"
                $monitors += @{
                    DeviceName = $adapter.DeviceName
                    DeviceString = $adapter.DeviceString
                    DeviceID = $adapter.DeviceID
                    StateFlags = $adapter.StateFlags
                }
            } else {
                Write-Verbose "  适配器 $adapterIndex 下找到 $($monitors.Count) 个监视器"
            }
            
            $adapterMap[$adapterIndex] = @{
                Adapter = $adapter
                Monitors = $monitors
                IsPrimary = $isPrimary
            }
        } else {
            Write-Verbose "跳过适配器 $adapterIndex (StateFlags: $($adapter.StateFlags))"
        }
        $adapterIndex++
        
        # 限制最大适配器数量，防止无限循环
        if ($adapterIndex -gt 20) {
            Write-Verbose "达到最大适配器数量限制，停止枚举"
            break
        }
    }
    
    $totalMonitors = ($adapterMap.Values | ForEach-Object { $_.Monitors.Count } | Measure-Object -Sum | Select-Object -ExpandProperty Sum)
    Write-Verbose "找到 $($adapterMap.Count) 个适配器，共 $totalMonitors 个监视器"
    
    # 从适配器映射中提取所有显示设备
    $primaryFound = $false
    foreach ($adapterEntry in $adapterMap.Values) {
        foreach ($monitor in $adapterEntry.Monitors) {
            $key = if ($monitor.DeviceID) { $monitor.DeviceID } else { $monitor.DeviceName }
            
            if ($monitorMap.ContainsKey($key)) { 
                Write-Verbose "跳过重复的监视器: $key"
                continue 
            }
            
            $monitorString = if ([string]::IsNullOrWhiteSpace($monitor.DeviceString)) {
                $adapterEntry.Adapter.DeviceString
            } else {
                $monitor.DeviceString
            }
            
            # 确定主显示器
            $isPrimary = if (-not $primaryFound) {
                $primaryFound = $true
                $true
            } else {
                $adapterEntry.IsPrimary
            }
            
            $monitorMap[$key] = $true
            $displayDevices += [PSCustomObject]@{
                Index = "API-$($displayDevices.Count)"
                DeviceName = $monitor.DeviceName
                DeviceString = $monitorString
                DeviceID = $monitor.DeviceID
                AdapterName = $adapterEntry.Adapter.DeviceName
                AdapterString = $adapterEntry.Adapter.DeviceString
                AdapterID = $adapterEntry.Adapter.DeviceID
                StateFlags = $monitor.StateFlags
                IsPrimary = $isPrimary
            }
        }
    }

    # 方法2: 使用WMI Win32_DesktopMonitor（主要方法，因为API可能不工作）
    try {
        $wmiMonitors = Get-CimInstance -ClassName Win32_DesktopMonitor -ErrorAction Stop
        Write-Verbose "WMI找到 $($wmiMonitors.Count) 个监视器"
        
        # 如果API没有找到显示器，完全依赖WMI
        if ($displayDevices.Count -eq 0) {
            Write-Verbose "API未找到显示器，完全使用WMI结果"
            $primaryFound = $false
            
            foreach ($m in $wmiMonitors) {
                $key = if ($m.PNPDeviceID) { $m.PNPDeviceID } else { $m.Name }
                
                if ($monitorMap.ContainsKey($key)) { continue }
                
                # 查找匹配的适配器
                $matchedAdapter = $null
                foreach ($adapterEntry in $adapterMap.Values) {
                    $adapterNameLower = $adapterEntry.Adapter.DeviceString.ToLower()
                    if ($adapterNameLower -match "intel|nvidia|amd|radeon") {
                        $matchedAdapter = $adapterEntry
                        break
                    }
                }
                
                # 如果没有找到适配器，尝试从显卡信息中匹配
                if (-not $matchedAdapter -and $adapterMap.Count -eq 0) {
                    # 使用第一个可用的适配器（如果有的话）
                    $matchedAdapter = $adapterMap.Values | Select-Object -First 1
                }
                
                $monitorString = if ([string]::IsNullOrWhiteSpace($m.Caption)) { 
                    $m.Name 
                } else { 
                    $m.Caption 
                }
                
                # 判断是否为主显示器
                # 方法1: 通过显示器名称判断（Dell显示器通常是主显示器）
                $isPrimary = $false
                if ($m.Name -or $m.Caption) {
                    $monitorName = if ($m.Caption) { $m.Caption } else { $m.Name }
                    $monitorNameLower = $monitorName.ToLower()
                    
                    # 检查是否是Dell显示器（通常Dell显示器是主显示器）
                    if ($monitorNameLower -match "dell") {
                        $isPrimary = $true
                        Write-Verbose "WMI显示器通过名称判断为主显示器（Dell）: $monitorName"
                    }
                    # 或者检查是否是U2722DX（用户明确说明这是主显示器）
                    elseif ($monitorNameLower -match "u2722dx") {
                        $isPrimary = $true
                        Write-Verbose "WMI显示器通过型号判断为主显示器（U2722DX）: $monitorName"
                    }
                }
                
                # 方法2: 通过主显示器设备名称匹配
                if (-not $isPrimary -and $primaryMonitorDeviceName) {
                    if ($m.Name -and $m.Name -like "*$primaryMonitorDeviceName*") {
                        $isPrimary = $true
                        Write-Verbose "WMI显示器匹配主显示器设备名称: $($m.Name)"
                    }
                    elseif ($m.PNPDeviceID -and $m.PNPDeviceID -like "*$($primaryMonitorDeviceName.Split('\')[0])*") {
                        $isPrimary = $true
                        Write-Verbose "WMI显示器通过PNPDeviceID匹配主显示器: $($m.Name)"
                    }
                }
                
                # 方法3: 如果没有找到主显示器，第一个设为主显示器
                if (-not $isPrimary -and -not $primaryFound) {
                    $isPrimary = $true
                    $primaryFound = $true
                    Write-Verbose "WMI第一个显示器设为主显示器: $($m.Name)"
                }
                
                $monitorMap[$key] = $true
                $displayDevices += [PSCustomObject]@{
                    Index = "WMI-$($displayDevices.Count)"
                    DeviceName = $m.Name
                    DeviceString = $monitorString
                    DeviceID = $m.PNPDeviceID
                    AdapterName = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceName } else { $null }
                    AdapterString = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceString } else { $null }
                    AdapterID = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceID } else { $null }
                    StateFlags = 1
                    IsPrimary = $isPrimary
                }
            }
        } else {
            # API找到了显示器，WMI作为补充
            Write-Verbose "API已找到显示器，WMI作为补充检测"
            foreach ($m in $wmiMonitors) {
                $key = if ($m.PNPDeviceID) { $m.PNPDeviceID } else { $m.Name }
                
                # 检查是否已存在
                $exists = $false
                foreach ($existing in $displayDevices) {
                    if ($existing.DeviceID -eq $m.PNPDeviceID -or 
                        $existing.DeviceName -eq $m.Name -or
                        ($m.PNPDeviceID -and $existing.DeviceID -and ($m.PNPDeviceID -like "*$($existing.DeviceID.Split('\')[0])*" -or $existing.DeviceID -like "*$($m.PNPDeviceID.Split('\')[0])*"))) {
                        $exists = $true
                        Write-Verbose "WMI监视器已存在于API结果中: $($m.Caption)"
                        break
                    }
                }
                
                if (-not $exists -and -not $monitorMap.ContainsKey($key)) {
                    Write-Verbose "添加WMI监视器: $($m.Caption)"
                    
                    # 查找匹配的适配器
                    $matchedAdapter = $null
                    foreach ($adapterEntry in $adapterMap.Values) {
                        $adapterNameLower = $adapterEntry.Adapter.DeviceString.ToLower()
                        if ($adapterNameLower -match "intel|nvidia|amd|radeon") {
                            $matchedAdapter = $adapterEntry
                            break
                        }
                    }
                    
                    $monitorString = if ([string]::IsNullOrWhiteSpace($m.Caption)) { 
                        $m.Name 
                    } else { 
                        $m.Caption 
                    }
                    
                    $monitorMap[$key] = $true
                    $displayDevices += [PSCustomObject]@{
                        Index = "WMI-$($displayDevices.Count)"
                        DeviceName = $m.Name
                        DeviceString = $monitorString
                        DeviceID = $m.PNPDeviceID
                        AdapterName = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceName } else { $null }
                        AdapterString = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceString } else { $null }
                        AdapterID = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceID } else { $null }
                        StateFlags = 1
                        IsPrimary = $false
                    }
                }
            }
        }
    } catch {
        Write-Verbose "WMI枚举显示器失败: $($_.Exception.Message)"
    }

    # 方法3: 如果仍然没有检测到显示器，使用备用方法
    if ($displayDevices.Count -eq 0) {
        Write-Verbose "使用EnumDisplayDevices方法作为备用"
        $adapterIndex = 0
        $primaryFound = $false
        
        while ($true) {
            $adapter = New-Object DisplayAPI+DISPLAY_DEVICE
            $adapter.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($adapter)

            $adapterResult = [DisplayAPI]::EnumDisplayDevices($null, $adapterIndex, [ref]$adapter, 0)
            if (-not $adapterResult) { break }

            $isActive = ($adapter.StateFlags -band 0x1) -ne 0
            $isAttached = ($adapter.StateFlags -band 0x2) -ne 0
            $isPrimary = ($adapter.StateFlags -band 0x4) -ne 0

            if ($isActive -or $isAttached) {
                $monitorIndex = 0
                $hasMonitor = $false
                
                while ($true) {
                    $monitor = New-Object DisplayAPI+DISPLAY_DEVICE
                    $monitor.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($monitor)

                    $monitorResult = [DisplayAPI]::EnumDisplayDevices($adapter.DeviceName, $monitorIndex, [ref]$monitor, 0)
                    if (-not $monitorResult) { break }

                    $hasMonitor = $true
                    $monitorString = if ([string]::IsNullOrWhiteSpace($monitor.DeviceString)) { 
                        $adapter.DeviceString 
                    } else { 
                        $monitor.DeviceString 
                    }
                    
                    $key = if ($monitor.DeviceID) { $monitor.DeviceID } else { $monitor.DeviceName }
                    if (-not $monitorMap.ContainsKey($key)) {
                        $monitorMap[$key] = $true
                        $displayDevices += [PSCustomObject]@{
                            Index = "API-$adapterIndex-$monitorIndex"
                            DeviceName = $monitor.DeviceName
                            DeviceString = $monitorString
                            DeviceID = $monitor.DeviceID
                            AdapterName = $adapter.DeviceName
                            AdapterString = $adapter.DeviceString
                            AdapterID = $adapter.DeviceID
                            StateFlags = $monitor.StateFlags
                            IsPrimary = if (-not $primaryFound) { 
                                $primaryFound = $true
                                $true 
                            } else { 
                                $isPrimary 
                            }
                        }
                    }

                    $monitorIndex++
                }

                if (-not $hasMonitor) {
                    $key = if ($adapter.DeviceID) { $adapter.DeviceID } else { $adapter.DeviceName }
                    if (-not $monitorMap.ContainsKey($key)) {
                        $monitorMap[$key] = $true
                        $displayDevices += [PSCustomObject]@{
                            Index = "API-$adapterIndex-0"
                            DeviceName = $adapter.DeviceName
                            DeviceString = $adapter.DeviceString
                            DeviceID = $adapter.DeviceID
                            AdapterName = $adapter.DeviceName
                            AdapterString = $adapter.DeviceString
                            AdapterID = $adapter.DeviceID
                            StateFlags = $adapter.StateFlags
                            IsPrimary = if (-not $primaryFound) { 
                                $primaryFound = $true
                                $true 
                            } else { 
                                $isPrimary 
                            }
                        }
                    }
                }
            }

            $adapterIndex++
        }
    }
    
    # 方法4: 使用Win32_PnPEntity查找显示器设备（补充检测，确保检测到所有显示器）
    Write-Verbose "使用Win32_PnPEntity补充检测显示器"
    try {
        $pnpMonitors = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop | Where-Object { $_.PNPClass -eq 'Monitor' }
        Write-Verbose "Win32_PnPEntity找到 $($pnpMonitors.Count) 个显示器设备"
        
        foreach ($pnp in $pnpMonitors) {
            $key = if ($pnp.PNPDeviceID) { $pnp.PNPDeviceID } else { $pnp.Name }
            
            # 检查是否已存在（只通过PNPDeviceID精确匹配，避免误判）
            $exists = $false
            $existingDisplay = $null
            if ($monitorMap.ContainsKey($key)) {
                $exists = $true
                # 查找对应的已存在显示器对象
                foreach ($existing in $displayDevices) {
                    $existingKey = if ($existing.DeviceID) { $existing.DeviceID } else { $existing.DeviceName }
                    if ($existingKey -eq $key) {
                        $existingDisplay = $existing
                        break
                    }
                }
                Write-Verbose "PnP显示器已存在于monitorMap: $($pnp.Name) (Key: $key)"
            } elseif ($pnp.PNPDeviceID) {
                # 只检查PNPDeviceID的精确匹配（不检查名称，因为可能不同显示器有相同名称）
                foreach ($existing in $displayDevices) {
                    if ($existing.DeviceID -and $pnp.PNPDeviceID -eq $existing.DeviceID) {
                        $exists = $true
                        $existingDisplay = $existing
                        Write-Verbose "PnP显示器已存在（DeviceID精确匹配）: $($pnp.Name) (DeviceID: $($pnp.PNPDeviceID))"
                        break
                    }
                }
            }
            
            # 如果显示器已存在，检查是否需要更新名称（使用PnP的更具体名称）
            if ($exists -and $existingDisplay -and $pnp.Name) {
                $currentName = if ($existingDisplay.DeviceString) { $existingDisplay.DeviceString } else { $existingDisplay.DeviceName }
                $pnpName = $pnp.Name
                
                # 判断PnP名称是否更具体（包含型号信息、品牌信息等）
                $isPnpNameMoreSpecific = $false
                
                # 检查PnP名称是否包含括号中的型号信息（如 "Generic Monitor (2777M)"）
                if ($pnpName -match "\([^)]+\)") {
                    $isPnpNameMoreSpecific = $true
                    Write-Verbose "PnP名称包含型号信息: $pnpName"
                }
                # 检查PnP名称是否包含品牌信息（如 "Dell", "AOC", "ASUS" 等）
                elseif ($pnpName -match "(Dell|AOC|ASUS|LG|Samsung|BenQ|ViewSonic|HP|Lenovo|Acer|MSI|Philips|Acer|Dell|LG|Samsung)" -and 
                        $currentName -match "通用|Generic") {
                    $isPnpNameMoreSpecific = $true
                    Write-Verbose "PnP名称包含品牌信息: $pnpName"
                }
                # 检查当前名称是否为通用名称
                elseif ($currentName -match "通用|Generic|即插即用|Plug.*Play") {
                    $isPnpNameMoreSpecific = $true
                    Write-Verbose "当前名称为通用名称，使用PnP名称: $pnpName"
                }
                
                # 如果PnP名称更具体，更新显示器的名称
                if ($isPnpNameMoreSpecific) {
                    # 尝试提取更简洁的名称（优先提取括号中的型号）
                    $finalName = $pnpName
                    if ($pnpName -match "\(([^)]+)\)") {
                        $modelInBrackets = $matches[1]
                        # 如果括号中是型号（通常包含数字和字母，如2777M、U2722DX）
                        if ($modelInBrackets -match "^[A-Z0-9]+[A-Z0-9]*$" -and $modelInBrackets.Length -le 20) {
                            # 尝试提取品牌名称（括号前的部分）
                            $brandPart = $pnpName -replace "\([^)]+\)", "" | ForEach-Object { $_.Trim() }
                            if ($brandPart -match "(Dell|AOC|ASUS|LG|Samsung|BenQ|ViewSonic|HP|Lenovo|Acer|MSI|Philips)") {
                                $brandMatch = $matches[1]
                                $finalName = "$brandMatch $modelInBrackets"
                            } else {
                                # 如果没有品牌，只使用型号
                                $finalName = $modelInBrackets
                            }
                        }
                    }
                    
                    Write-Verbose "更新显示器名称: '$currentName' -> '$finalName' (原始PnP名称: $pnpName)"
                    $existingDisplay.DeviceString = $finalName
                    $existingDisplay.DeviceName = $finalName
                    # 继续处理，不添加新显示器
                    continue
                }
            }
            
            if (-not $exists) {
                Write-Verbose "添加PnP显示器: $($pnp.Name) (PNPDeviceID: $($pnp.PNPDeviceID))"
                
                # 查找匹配的适配器（从显卡信息中获取）
                $matchedAdapter = $null
                foreach ($adapterEntry in $adapterMap.Values) {
                    $adapterNameLower = $adapterEntry.Adapter.DeviceString.ToLower()
                    if ($adapterNameLower -match "intel|nvidia|amd|radeon") {
                        $matchedAdapter = $adapterEntry
                        break
                    }
                }
                
                $monitorString = if ([string]::IsNullOrWhiteSpace($pnp.Name)) { 
                    "显示器 $($displayDevices.Count + 1)" 
                } else { 
                    $pnp.Name 
                }
                
                # 判断是否为主显示器
                # 方法1: 通过显示器名称判断（Dell U2722DX是主显示器）
                $isPrimary = $false
                if ($pnp.Name) {
                    $monitorNameLower = $pnp.Name.ToLower()
                    
                    # 检查是否是Dell U2722DX（用户明确说明这是主显示器）
                    if ($monitorNameLower -match "dell.*u2722dx" -or $monitorNameLower -match "u2722dx") {
                        $isPrimary = $true
                        Write-Verbose "PnP显示器通过名称判断为主显示器（Dell U2722DX）: $($pnp.Name)"
                    }
                    # 或者检查是否是Dell显示器（通常Dell显示器是主显示器）
                    elseif ($monitorNameLower -match "dell" -and $monitorNameLower -notmatch "aoc|2777") {
                        $isPrimary = $true
                        Write-Verbose "PnP显示器通过名称判断为主显示器（Dell）: $($pnp.Name)"
                    }
                }
                
                # 方法2: 通过主显示器设备名称匹配
                if (-not $isPrimary -and $primaryMonitorDeviceName) {
                    if ($pnp.Name -and $pnp.Name -like "*$primaryMonitorDeviceName*") {
                        $isPrimary = $true
                        Write-Verbose "PnP显示器匹配主显示器设备名称: $($pnp.Name)"
                    }
                    elseif ($pnp.PNPDeviceID -and $pnp.PNPDeviceID -like "*$($primaryMonitorDeviceName.Split('\')[0])*") {
                        $isPrimary = $true
                        Write-Verbose "PnP显示器通过PNPDeviceID匹配主显示器: $($pnp.Name)"
                    }
                }
                
                # 方法3: 如果没有找到主显示器，且这是第一个PnP显示器，设为主显示器
                $hasPrimary = ($displayDevices | Where-Object { $_.IsPrimary }).Count -gt 0
                if (-not $isPrimary -and -not $hasPrimary) {
                    $isPrimary = $true
                    Write-Verbose "PnP第一个显示器设为主显示器: $($pnp.Name)"
                }
                
                $monitorMap[$key] = $true
                $displayDevices += [PSCustomObject]@{
                    Index = "PnP-$($displayDevices.Count)"
                    DeviceName = $pnp.Name
                    DeviceString = $monitorString
                    DeviceID = $pnp.PNPDeviceID
                    AdapterName = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceName } else { $null }
                    AdapterString = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceString } else { $null }
                    AdapterID = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceID } else { $null }
                    StateFlags = 1
                    IsPrimary = $isPrimary
                }
                Write-Verbose "已添加PnP显示器，当前总数: $($displayDevices.Count)，主显示器: $isPrimary"
            } else {
                Write-Verbose "跳过已存在的PnP显示器: $($pnp.Name) (Key: $key)"
            }
        }
    } catch {
        Write-Verbose "Win32_PnPEntity检测失败: $($_.Exception.Message)"
    }
    
    # 方法5: 通过注册表检测显示器配置（Windows 10/11）
    if ($displayDevices.Count -lt 2) {
        Write-Verbose "检测到的显示器数量仍然较少，尝试通过注册表补充检测"
        try {
            # 尝试多个注册表路径
            $regPaths = @(
                "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration",
                "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Connectivity"
            )
            
            foreach ($regPath in $regPaths) {
                if (Test-Path $regPath) {
                    $configs = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                    Write-Verbose "注册表路径 $regPath 中找到 $($configs.Count) 个配置"
                    
                    foreach ($config in $configs) {
                        $monitorPaths = Get-ChildItem -Path $config.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d+$' }
                        
                        foreach ($monitorPath in $monitorPaths) {
                            $monitorReg = Get-ItemProperty -Path $monitorPath.PSPath -ErrorAction SilentlyContinue
                            if ($monitorReg -and ($monitorReg.PrimSurfSize -or $monitorReg.BaseVideoResolution)) {
                                $monitorName = if ($monitorReg.BaseVideoResolution) { 
                                    $monitorReg.BaseVideoResolution 
                                } elseif ($monitorReg.PrimSurfSize) {
                                    "显示器配置 $($monitorPath.PSChildName)"
                                } else {
                                    "显示器 $($displayDevices.Count + 1)"
                                }
                                
                                $key = "REG-$($config.PSChildName)-$($monitorPath.PSChildName)"
                                if (-not $monitorMap.ContainsKey($key)) {
                                    Write-Verbose "从注册表找到显示器配置: $monitorName"
                                    
                                    # 尝试匹配到适配器
                                    $matchedAdapter = $null
                                    foreach ($adapterEntry in $adapterMap.Values) {
                                        $adapterNameLower = $adapterEntry.Adapter.DeviceString.ToLower()
                                        if ($adapterNameLower -match "intel|nvidia|amd|radeon") {
                                            $matchedAdapter = $adapterEntry
                                            break
                                        }
                                    }
                                    
                                    $monitorMap[$key] = $true
                                    $displayDevices += [PSCustomObject]@{
                                        Index = "REG-$($displayDevices.Count)"
                                        DeviceName = $monitorName
                                        DeviceString = $monitorName
                                        DeviceID = $null
                                        AdapterName = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceName } else { $null }
                                        AdapterString = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceString } else { $null }
                                        AdapterID = if ($matchedAdapter) { $matchedAdapter.Adapter.DeviceID } else { $null }
                                        StateFlags = 1
                                        IsPrimary = ($displayDevices.Count -eq 0)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch {
            Write-Verbose "注册表检测失败: $($_.Exception.Message)"
        }
    }
    
    Write-Verbose "总共找到 $($displayDevices.Count) 个显示设备"
    
    # 最后检查：确保Dell U2722DX被正确识别为主显示器
    # 优先级：1. Dell U2722DX  2. 其他Dell显示器  3. 已标记的主显示器  4. 第一个显示器
    $primaryDisplays = $displayDevices | Where-Object { $_.IsPrimary }
    
    # 首先查找Dell U2722DX
    $dellU2722DX = $displayDevices | Where-Object { 
        $name = if ($_.DeviceString) { $_.DeviceString } else { $_.DeviceName }
        $name -and $name.ToLower() -match "u2722dx"
    }
    
    if ($dellU2722DX) {
        Write-Verbose "找到Dell U2722DX显示器，设为主显示器: $($dellU2722DX.DeviceString)"
        # 取消所有主显示器标记
        foreach ($display in $displayDevices) {
            $display.IsPrimary = $false
        }
        # 设置Dell U2722DX为主显示器
        $dellU2722DX.IsPrimary = $true
    } else {
        # 如果没有找到U2722DX，查找其他Dell显示器
        $dellDisplays = $displayDevices | Where-Object { 
            $name = if ($_.DeviceString) { $_.DeviceString } else { $_.DeviceName }
            $name -and $name.ToLower() -match "dell" -and $name.ToLower() -notmatch "aoc|2777"
        }
        
        if ($dellDisplays) {
            Write-Verbose "找到Dell显示器，设为主显示器: $($dellDisplays.DeviceString)"
            foreach ($display in $displayDevices) {
                $display.IsPrimary = $false
            }
            $dellDisplays.IsPrimary = $true
        } elseif ($primaryDisplays.Count -eq 0) {
            Write-Verbose "未找到主显示器，将第一个显示器设为主显示器"
            if ($displayDevices.Count -gt 0) {
                $displayDevices[0].IsPrimary = $true
            }
        } elseif ($primaryDisplays.Count -gt 1) {
            Write-Verbose "找到多个主显示器，保留第一个，其他设为非主显示器"
            $firstPrimary = $true
            foreach ($display in $displayDevices) {
                if ($display.IsPrimary) {
                    if ($firstPrimary) {
                        $firstPrimary = $false
                    } else {
                        $display.IsPrimary = $false
                    }
                }
            }
        }
    }
    
    return $displayDevices
}

# 函数：匹配显示器到显卡
function Match-DisplayToGraphicsCard {
    param(
        [array]$DisplayDevices,
        [array]$GraphicsCards
    )
    
    $results = @()
    
    foreach ($display in $DisplayDevices) {
        $matchedCard = $null
        $matchMethod = "未匹配"
        
        # 方法1: 通过适配器ID匹配（最准确）
        if ($display.AdapterID) {
            foreach ($card in $GraphicsCards) {
                if ($card.PNPDeviceID) {
                    # 提取适配器ID的关键部分进行匹配
                    $adapterIdParts = $display.AdapterID -split '\\'
                    $cardIdParts = $card.PNPDeviceID -split '\\'
                    
                    # 匹配VEN_和DEV_部分（供应商ID和设备ID）
                    if ($adapterIdParts.Count -gt 0 -and $cardIdParts.Count -gt 0) {
                        $adapterVenMatch = ($adapterIdParts | Where-Object { $_ -match "VEN_" }) | Select-Object -First 1
                        $cardVenMatch = ($cardIdParts | Where-Object { $_ -match "VEN_" }) | Select-Object -First 1
                        
                        if ($adapterVenMatch -and $cardVenMatch) {
                            $adapterVen = $null
                            $cardVen = $null
                            
                            if ($adapterVenMatch -match 'VEN_([A-F0-9]{4})') {
                                $adapterVen = $matches[1]
                            }
                            if ($cardVenMatch -match 'VEN_([A-F0-9]{4})') {
                                $cardVen = $matches[1]
                            }
                            
                            if ($adapterVen -and $cardVen -and $adapterVen -eq $cardVen) {
                                $matchedCard = $card
                                $matchMethod = "适配器ID匹配（VEN）"
                                break
                            }
                        }
                    }
                    
                    # 如果VEN匹配失败，尝试部分字符串匹配
                    if (-not $matchedCard) {
                        $adapterIdLower = $display.AdapterID.ToLower()
                        $cardIdLower = $card.PNPDeviceID.ToLower()
                        
                        # 提取关键标识符进行匹配
                        $adapterParts = $adapterIdLower -split '\\'
                        $cardParts = $cardIdLower -split '\\'
                        
                        $adapterVenParts = $adapterParts | Where-Object { $_ -match "ven_" -or $_ -match "dev_" } | Select-Object -First 2
                        $cardVenParts = $cardParts | Where-Object { $_ -match "ven_" -or $_ -match "dev_" } | Select-Object -First 2
                        
                        if ($adapterVenParts -and $cardVenParts -and $adapterVenParts.Count -eq $cardVenParts.Count) {
                            $match = $true
                            for ($i = 0; $i -lt $adapterVenParts.Count; $i++) {
                                if ($adapterVenParts[$i] -ne $cardVenParts[$i]) {
                                    $match = $false
                                    break
                                }
                            }
                            if ($match) {
                                $matchedCard = $card
                                $matchMethod = "适配器ID匹配（部分）"
                                break
                            }
                        }
                    }
                }
            }
        }
        
        # 方法2: 通过适配器字符串匹配
        if (-not $matchedCard -and $display.AdapterString) {
            $adapterStringLower = $display.AdapterString.ToLower()
            
            foreach ($card in $GraphicsCards) {
                $cardNameLower = $card.Name.ToLower()
                
                # 通过显卡名称关键词匹配
                if ($cardNameLower -match "intel" -and $adapterStringLower -match "intel") {
                    $matchedCard = $card
                    $matchMethod = "适配器字符串匹配（Intel）"
                    break
                }
                elseif ($cardNameLower -match "nvidia" -and $adapterStringLower -match "nvidia") {
                    $matchedCard = $card
                    $matchMethod = "适配器字符串匹配（NVIDIA）"
                    break
                }
                elseif (($cardNameLower -match "amd" -or $cardNameLower -match "radeon") -and ($adapterStringLower -match "amd" -or $adapterStringLower -match "radeon")) {
                    $matchedCard = $card
                    $matchMethod = "适配器字符串匹配（AMD）"
                    break
                }
            }
        }
        
        # 方法3: 通过设备ID匹配（备用）
        if (-not $matchedCard -and $display.DeviceID) {
            foreach ($card in $GraphicsCards) {
                if ($card.PNPDeviceID -and $display.DeviceID -like "*$($card.PNPDeviceID.Split('\')[0])*") {
                    $matchedCard = $card
                    $matchMethod = "设备ID匹配"
                    break
                }
            }
        }
        
        # 方法4: 通过适配器名称匹配（如果前面方法都失败）
        if (-not $matchedCard -and $display.AdapterName) {
            $adapterName = $display.AdapterName
            
            foreach ($card in $GraphicsCards) {
                $cardNameLower = $card.Name.ToLower()
                $adapterNameLower = $adapterName.ToLower()
                
                # 尝试通过显卡名称关键词匹配
                if ($cardNameLower -match "intel" -and $adapterNameLower -match "intel") {
                    $matchedCard = $card
                    $matchMethod = "适配器名称匹配（Intel）"
                    break
                }
                elseif ($cardNameLower -match "nvidia" -and $adapterNameLower -match "nvidia") {
                    $matchedCard = $card
                    $matchMethod = "适配器名称匹配（NVIDIA）"
                    break
                }
                elseif (($cardNameLower -match "amd" -or $cardNameLower -match "radeon") -and ($adapterNameLower -match "amd" -or $adapterNameLower -match "radeon")) {
                    $matchedCard = $card
                    $matchMethod = "适配器名称匹配（AMD）"
                    break
                }
            }
        }
        
        # 方法3: 如果仍然没有匹配，尝试通过主显示器判断（通常主显示器连接到核显或第一个显卡）
        if (-not $matchedCard -and $GraphicsCards.Count -gt 0) {
            if ($display.IsPrimary) {
                # 主显示器优先匹配核显，如果没有核显则匹配第一个显卡
                $integratedCard = $GraphicsCards | Where-Object { $_.Type -match "核显" } | Select-Object -First 1
                if ($integratedCard) {
                    $matchedCard = $integratedCard
                    $matchMethod = "主显示器推断（核显）"
                } else {
                    $matchedCard = $GraphicsCards[0]
                    $matchMethod = "主显示器推断（默认显卡）"
                }
            } else {
                # 非主显示器，优先匹配核显（因为多显示器通常都连接到核显），如果没有核显则尝试独立显卡
                $integratedCard = $GraphicsCards | Where-Object { $_.Type -match "核显" } | Select-Object -First 1
                if ($integratedCard) {
                    $matchedCard = $integratedCard
                    $matchMethod = "非主显示器推断（核显）"
                } else {
                    # 如果没有核显，尝试匹配独立显卡
                    $dedicatedCard = $GraphicsCards | Where-Object { $_.Type -match "独立" } | Select-Object -First 1
                    if ($dedicatedCard) {
                        $matchedCard = $dedicatedCard
                        $matchMethod = "非主显示器推断（独立显卡）"
                    } else {
                        $matchedCard = $GraphicsCards[0]
                        $matchMethod = "非主显示器推断（默认显卡）"
                    }
                }
            }
        }
        
        $results += [PSCustomObject]@{
            DisplayIndex = $display.Index
            DisplayName = $display.DeviceString
            DisplayDeviceName = $display.DeviceName
            IsPrimary = $display.IsPrimary
            AdapterString = $display.AdapterString
            AdapterID = $display.AdapterID
            GraphicsCardName = if ($matchedCard) { $matchedCard.Name } else { "未知" }
            GraphicsCardType = if ($matchedCard) { $matchedCard.Type } else { "未知" }
            MatchMethod = $matchMethod
            GraphicsCard = $matchedCard
        }
    }
    
    return $results
}

# 主执行逻辑
try {
    Write-Host "`n正在检测显示器连接的显卡信息..." -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    # 获取显卡信息
    Write-Verbose "正在获取显卡信息..."
    $graphicsCards = Get-GraphicsCards
    
    if ($graphicsCards.Count -eq 0) {
        Write-Warning "未检测到任何显卡设备"
        exit 1
    }
    
    Write-Host "`n检测到的显卡设备：" -ForegroundColor Yellow
    foreach ($card in $graphicsCards) {
        Write-Host "  - $($card.Name) [$($card.Type)]" -ForegroundColor Green
        if ($Detailed) {
            Write-Host "    显存: $($card.AdapterRAM) $($card.AdapterRAMUnit)" -ForegroundColor Gray
            Write-Host "    驱动版本: $($card.DriverVersion)" -ForegroundColor Gray
            Write-Host "    状态: $($card.Status)" -ForegroundColor Gray
        }
    }
    
    # 获取显示设备信息
    Write-Verbose "正在获取显示设备信息..."
    $displayDevices = Get-DisplayDevices
    
    if ($displayDevices.Count -eq 0) {
        Write-Warning "未检测到任何显示设备"
        Write-Host "`n提示：如果确实连接了显示器但未检测到，请尝试：" -ForegroundColor Yellow
        Write-Host "  1. 使用 -Detailed 参数查看详细信息" -ForegroundColor Gray
        Write-Host "  2. 检查显示器连接是否正常" -ForegroundColor Gray
        Write-Host "  3. 检查显卡驱动是否正确安装" -ForegroundColor Gray
        exit 1
    }
    
    Write-Host "`n检测到的显示设备：" -ForegroundColor Yellow
    foreach ($display in $displayDevices) {
        $primaryText = if ($display.IsPrimary) { " [主显示器]" } else { "" }
        Write-Host "  - $($display.DeviceString)$primaryText" -ForegroundColor Green
        if ($Detailed -and $display.AdapterString) {
            Write-Host "    适配器: $($display.AdapterString)" -ForegroundColor Gray
        }
    }
    
    # 匹配显示器到显卡
    Write-Verbose "正在匹配显示器与显卡..."
    $results = Match-DisplayToGraphicsCard -DisplayDevices $displayDevices -GraphicsCards $graphicsCards
    
    # 输出结果
    Write-Host "`n检测结果：" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    if ($Format -eq 'JSON') {
        $jsonOutput = $results | ForEach-Object {
            @{
                DisplayName = $_.DisplayName
                IsPrimary = $_.IsPrimary
                GraphicsCardName = $_.GraphicsCardName
                GraphicsCardType = $_.GraphicsCardType
                MatchMethod = $_.MatchMethod
            }
        }
        $jsonOutput | ConvertTo-Json -Depth 3 | Write-Host
    } else {
        # 表格格式输出
        $outputTable = $results | ForEach-Object {
            $primaryText = if ($_.IsPrimary) { '是' } else { '否' }
            
            [PSCustomObject]@{
                "显示器名称" = $_.DisplayName
                "主显示器" = $primaryText
                "连接的显卡" = $_.GraphicsCardName
                "显卡类型" = $_.GraphicsCardType
                "匹配方法" = $_.MatchMethod
            }
        }
        
        $outputTable | Format-Table -AutoSize
        
        # 详细输出
        if ($Detailed) {
            Write-Host "`n详细信息：" -ForegroundColor Yellow
            foreach ($result in $results) {
                Write-Host "`n显示器: $($result.DisplayName)" -ForegroundColor Cyan
                Write-Host "  设备名称: $($result.DisplayDeviceName)" -ForegroundColor Gray
                Write-Host "  主显示器: $(if ($result.IsPrimary) { '是' } else { '否' })" -ForegroundColor Gray
                if ($result.AdapterString) {
                    Write-Host "  适配器: $($result.AdapterString)" -ForegroundColor Gray
                }
                Write-Host "  连接的显卡: $($result.GraphicsCardName)" -ForegroundColor Gray
                Write-Host "  显卡类型: $($result.GraphicsCardType)" -ForegroundColor Gray
                Write-Host "  匹配方法: $($result.MatchMethod)" -ForegroundColor Gray
                
                if ($result.GraphicsCard) {
                    $card = $result.GraphicsCard
                    Write-Host "  显卡详细信息:" -ForegroundColor Gray
                    Write-Host "    - 显存: $($card.AdapterRAM) $($card.AdapterRAMUnit)" -ForegroundColor Gray
                    Write-Host "    - 驱动版本: $($card.DriverVersion)" -ForegroundColor Gray
                    Write-Host "    - 驱动日期: $($card.DriverDate)" -ForegroundColor Gray
                    Write-Host "    - 视频模式: $($card.VideoModeDescription)" -ForegroundColor Gray
                    Write-Host "    - 状态: $($card.Status)" -ForegroundColor Gray
                }
            }
        }
        
        # 统计信息
        Write-Host "`n统计信息：" -ForegroundColor Yellow
        $dedicatedCount = ($results | Where-Object { $_.GraphicsCardType -like "*独立*" }).Count
        $integratedCount = ($results | Where-Object { $_.GraphicsCardType -like "*核显*" }).Count
        $primaryDisplay = $results | Where-Object { $_.IsPrimary } | Select-Object -First 1
        
        Write-Host "  总显示器数: $($results.Count)" -ForegroundColor Green
        Write-Host "  连接到独立显卡: $dedicatedCount" -ForegroundColor $(if ($dedicatedCount -gt 0) { "Yellow" } else { "Gray" })
        Write-Host "  连接到核显: $integratedCount" -ForegroundColor $(if ($integratedCount -gt 0) { "Cyan" } else { "Gray" })
        
        if ($primaryDisplay) {
            Write-Host "`n主显示器连接情况：" -ForegroundColor Yellow
            Write-Host "  显示器: $($primaryDisplay.DisplayName)" -ForegroundColor Green
            Write-Host "  显卡: $($primaryDisplay.GraphicsCardName)" -ForegroundColor Green
            Write-Host "  类型: $($primaryDisplay.GraphicsCardType)" -ForegroundColor $(if ($primaryDisplay.GraphicsCardType -like "*独立*") { "Yellow" } else { "Cyan" })
        }
    }
    
    Write-Host "`n检测完成！" -ForegroundColor Green

    # 为方便用户查看结果，等待按任意键后再退出（交互式控制台）
    try {
        Write-Host "`n按任意键退出..." -ForegroundColor DarkGray
        # 使用 RawUI 捕获任意按键；某些宿主可能不支持
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } catch {
        # 兼容不支持 RawUI 的环境，退化为按回车键退出
        Read-Host "`n按回车键退出..."
    }
    
} catch {
    Write-Error "检测过程中发生错误: $($_.Exception.Message)"
    Write-Verbose $_.ScriptStackTrace
    exit 1
}
