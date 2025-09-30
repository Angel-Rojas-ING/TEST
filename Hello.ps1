function Run-Trusted([String]$command) {
  Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue
  $service = Get-WmiObject -Class Win32_Service -Filter "Name='TrustedInstaller'"
  $DefaultBinPath = $service.PathName
  $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
  $base64Command = [Convert]::ToBase64String($bytes)
  sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
  sc.exe start TrustedInstaller | Out-Null
  sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
  Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue
}

$downloadCommand = @"
New-Item -Path 'C:\Users\Public' -ItemType Directory -Force
Set-Location 'C:\Users\Public'
Invoke-WebRequest -Uri 'https://github.com/Angel-Rojas-ING/Guia-Avanzada-de-Evil-Twins/archive/refs/heads/main.zip' -OutFile 'EvilTwins.zip' -ErrorAction Stop
Expand-Archive 'EvilTwins.zip' -DestinationPath 'C:\Users\Public' -Force
Remove-Item 'EvilTwins.zip' -Force
"@

Write-Host 'Downloading Evil Twins Guide to C:\Users\Public...'
Run-Trusted -command $downloadCommand
Write-Host 'Download completed!'
