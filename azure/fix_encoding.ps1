$path = 'c:\github\api-centric-ai-security\azure\deploy.ps1'
$content = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
$utf8bom = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($path, $content, $utf8bom)
Write-Host "Saved with UTF-8 BOM"

# Verify: first 3 bytes should be EF BB BF
$bytes = [System.IO.File]::ReadAllBytes($path)
Write-Host "First 3 bytes: $($bytes[0]) $($bytes[1]) $($bytes[2])  (expect 239 187 191)"
