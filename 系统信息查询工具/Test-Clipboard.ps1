# 剪切板功能测试脚本
# 用于验证Set-Clipboard命令是否可用

Write-Host "测试剪切板功能..." -ForegroundColor Yellow

try {
    $testContent = @(
        "剪切板功能测试",
        "测试时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "如果您能看到这些内容，说明剪切板功能正常"
    )
    
    $clipboardText = $testContent -join "`r`n"
    $clipboardText | Set-Clipboard
    
    Write-Host "✅ 剪切板功能正常！" -ForegroundColor Green
    Write-Host "测试内容已复制到剪切板，请尝试粘贴验证" -ForegroundColor White
}
catch {
    Write-Host "❌ 剪切板功能异常: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "可能的解决方案：" -ForegroundColor Yellow
    Write-Host "1. 重启PowerShell" -ForegroundColor White
    Write-Host "2. 检查是否有其他程序占用剪切板" -ForegroundColor White
    Write-Host "3. 联系IT管理员" -ForegroundColor White
}

Write-Host ""
Write-Host "按任意键退出..." -ForegroundColor White
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")