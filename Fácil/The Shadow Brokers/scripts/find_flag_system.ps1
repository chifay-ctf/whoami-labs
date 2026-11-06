# Busqueda de flag en ubicaciones accesibles solo como SYSTEM
# Recorrido sin seguir junctions/reparse points (evita bucles en AppData)
$ErrorActionPreference = 'SilentlyContinue'
$out = 'C:\Windows\Temp\flag_file_search.txt'
$patterns = @('WHOAMI\{','FLAG\{','CTF\{','HTB\{','THM\{','BANDERA\{','SHADOW\{','MS17\{')
$namePatterns = @('*flag*','*bandera*','*secret*','*password*')
$textExt = @('.txt','.log','.ini','.xml','.config','.bat','.cmd','.ps1','.vbs','.reg','.json','.yml','.yaml','.html','.htm','.md','.csv','.inf','.dat','.sql','.rtf','.manifest','.policy')
$dirs = @(
  'C:\System Volume Information',
  'C:\Windows\System32\config',
  'C:\Windows\System32\config\RegBack',
  'C:\Windows\System32\config\systemprofile',
  'C:\Windows\ServiceProfiles',
  'C:\Windows\Temp',
  'C:\Windows\Panther',
  'C:\Windows\System32\Tasks',
  'C:\Windows\System32\LogFiles',
  'C:\Windows\System32\winevt\Logs',
  'C:\Windows\System32\spool',
  'C:\Windows\System32\MsDtc',
  'C:\Windows\System32\SMI',
  'C:\Windows\System32\catroot2',
  'C:\Windows\System32\wbem\Repository',
  'C:\Windows\System32\Microsoft\Protect',
  'C:\$Recycle.Bin',
  'C:\ProgramData',
  'C:\Users\Administrator',
  'C:\Users\student',
  'C:\Users\Zero'
)

"=== SYSTEM FILE FLAG SEARCH ===" | Out-File -FilePath $out -Encoding ASCII
"User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" | Out-File -FilePath $out -Append -Encoding ASCII
"Date: $(Get-Date -Format s)" | Out-File -FilePath $out -Append -Encoding ASCII
"`nProtected paths:" | Out-File -FilePath $out -Append -Encoding ASCII
$accessible = 0
foreach ($d in $dirs) {
  if (Test-Path -LiteralPath $d) {
    "  [OK] $d" | Out-File -FilePath $out -Append -Encoding ASCII
    $accessible++
  } else {
    "  [NO] $d" | Out-File -FilePath $out -Append -Encoding ASCII
  }
}

$nameHits = @()
$contentHits = @()
foreach ($root in $dirs) {
  if (-not (Test-Path -LiteralPath $root)) { continue }
  $stack = New-Object System.Collections.Stack
  $stack.Push($root)
  while ($stack.Count -gt 0) {
    $dir = $stack.Pop()
    $items = Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue
    foreach ($i in $items) {
      if ($i.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
      if ($i.PSIsContainer) { $stack.Push($i.FullName); continue }
      foreach ($n in $namePatterns) {
        if ($i.Name -like $n) { $nameHits += $i.FullName; break }
      }
      if (($textExt -contains $i.Extension.ToLower()) -and ($i.Length -le 20MB) -and ($i.FullName -ne $out) -and ($i.Name -ne 'find_flag_system.ps1')) {
        $hit = Select-String -LiteralPath $i.FullName -Pattern $patterns -List -ErrorAction SilentlyContinue
        if ($hit) { $contentHits += "$($i.FullName): $($hit.Line.Trim())" }
      }
    }
  }
}

$nameHits = $nameHits | Sort-Object -Unique
$contentHits = $contentHits | Sort-Object -Unique
"`nFilename matches:" | Out-File -FilePath $out -Append -Encoding ASCII
$nameHits | ForEach-Object { "  $_" | Out-File -FilePath $out -Append -Encoding ASCII }
"  Total: $($nameHits.Count)" | Out-File -FilePath $out -Append -Encoding ASCII
"`nContent matches:" | Out-File -FilePath $out -Append -Encoding ASCII
$contentHits | ForEach-Object { "  $_" | Out-File -FilePath $out -Append -Encoding ASCII }
"  Total: $($contentHits.Count)" | Out-File -FilePath $out -Append -Encoding ASCII
"`nDone." | Out-File -FilePath $out -Append -Encoding ASCII

Write-Host "=== SYSTEM FILE FLAG SEARCH ==="
Write-Host "User      : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host "Paths OK  : $accessible / $($dirs.Count)"
Write-Host "Filenames : $($nameHits.Count)"
Write-Host "Contents  : $($contentHits.Count)"
Write-Host "Report    : $out"
if ($nameHits.Count -gt 0) { Write-Host "`nFilename hits:"; $nameHits | ForEach-Object { Write-Host "  $_" } }
if ($contentHits.Count -gt 0) { Write-Host "`nContent hits:"; $contentHits | ForEach-Object { Write-Host "  $_" } }
