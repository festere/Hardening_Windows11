##########################################################################################
# Demarage du script
##########################################################################################


#Elevation des priviledges
Write-Output "Elevation des priviledges..."
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)


#Nom de la fenetre
$Host.UI.RawUI.WindowTitle = "Hardening_Windows $([char]0x00A9)" 
vssadmin delete shadows /all /quiet | Out-Null


#Creation d'un point de restauration
Write-Host "Creation d'un point de restauration..."
New-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Type "DWORD" -Value 0 -Force
Checkpoint-Computer -Description "Hardening_Windows" -RestorePointType MODIFY_SETTINGS
Write-Host "Point de restauration créé avec succès !" -ForegroundColor Green


##########################################################################################
# Parametrage de Windows Defender
##########################################################################################
Write-Host "Le parametrage de Windows Defender commence..." -ForegroundColor Yellow

#Set Directory to PSScriptRoot
if ((Get-Location).Path -NE $PSScriptRoot) { 
    Set-Location $PSScriptRoot 
}

Write-Host "Enabling Windows Defender Protections and Features" -ForegroundColor Green -BackgroundColor Black

Write-Host "Copying Files to Supported Directories"
#Windows Defender Configuration Files
mkdir "C:\temp\Windows Defender"; Copy-Item -Path .\Files\"Windows Defender Configuration Files"\* -Destination C:\temp\"Windows Defender"\ -Force -Recurse -ErrorAction SilentlyContinue

Write-Host "Enabling Windows Defender Exploit Protections..."
#Enable Windows Defender Exploit Protection
Set-ProcessMitigation -PolicyFilePath "C:\temp\Windows Defender\DOD_EP_V3.xml"

$PolicyPath = "C:\temp\Windows Defender\CIP\WDAC_V1_Recommended_Audit\*.cip"
#https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deployment/deploy-wdac-policies-with-script
ForEach ($Policy in (Get-ChildItem -Recurse $PolicyPath).Fullname) {
  $PolicyBinary = "$Policy"
  $DestinationFolder = $env:windir+"\System32\CodeIntegrity\CIPolicies\Active\"
  $RefreshPolicyTool = "./Files/EXECUTABLES/RefreshPolicy(AMD64).exe"
  Copy-Item -Path $PolicyBinary -Destination $DestinationFolder -Force
  & $RefreshPolicyTool
}

Write-Host "Enabling Windows Defender Features..."
#https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSetting
#https://social.technet.microsoft.com/wiki/contents/articles/52251.manage-windows-defender-using-powershell.aspx
#https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps
#Enable real-time monitoring
Write-Host " -Enabling real-time monitoring"
Set-MpPreference -DisableRealtimeMonitoring $false
#Enable cloud-deliveredprotection
Write-Host " -Enabling cloud-deliveredprotection"
Set-MpPreference -MAPSReporting Advanced
#Enable sample submission
Write-Host " -Disabling sample submission"
Set-MpPreference -SubmitSamplesConsent Never
#Enable checking signatures before scanning
Write-Host " -Enabling checking signatures before scanning"
Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
#Enable behavior monitoring
Write-Host " -Enabling behavior monitoring"
Set-MpPreference -DisableBehaviorMonitoring $false
#Enable IOAV protection
Write-Host " -Enabling IOAV protection"
Set-MpPreference -DisableIOAVProtection $false
#Enable script scanning
Write-Host " -Enabling script scanning"
Set-MpPreference -DisableScriptScanning $false
#Enable removable drive scanning
Write-Host " -Enabling removable drive scanning"
Set-MpPreference -DisableRemovableDriveScanning $false
#Enable Block at first sight
Write-Host " -Enabling Block at first sight"
Set-MpPreference -DisableBlockAtFirstSeen $false
#Enable potentially unwanted apps
Write-Host " -Enabling potentially unwanted apps"
Set-MpPreference -PUAProtection 1
#Enable archive scanning
Write-Host " -Enabling archive scanning"
Set-MpPreference -DisableArchiveScanning $false
#Enable email scanning
Write-Host " -Enabling email scanning"
Set-MpPreference -DisableEmailScanning $false
#Enable File Hash Computation
Write-Host " -Enabling File Hash Computation"
Set-MpPreference -EnableFileHashComputation $true
#Enable Intrusion Prevention System
Write-Host " -Enabling Intrusion Prevention System"
Set-MpPreference -DisableIntrusionPreventionSystem $false
#Enable SSH Parcing
Write-Host " -Enabling SSH Parsing"
Set-MpPreference -DisableSshParsing $false
#Enable TLS Parcing
Write-Host " -Enabling TLS Parsing"
Set-MpPreference -DisableSshParsing $false
#Enable SSH Parcing
Write-Host " -Enabling SSH Parsing"
Set-MpPreference -DisableSshParsing $false
#Enable DNS Parcing
Write-Host " -Enabling DNS Parsing"
Set-MpPreference -DisableDnsParsing $false
Set-MpPreference -DisableDnsOverTcpParsing $false
#Enable DNS Sinkhole 
Write-Host " -Enabling DNS Sinkhole"
Set-MpPreference -EnableDnsSinkhole $true
#Enable Controlled Folder Access and setting to block mode
Write-Host " -Enabling Controlled Folder Access and setting to block mode"
Set-MpPreference -EnableControlledFolderAccess Enabled
#Enable Network Protection and setting to block mode
Write-Host " -Enabling Network Protection and setting to block mode"
Set-MpPreference -EnableNetworkProtection Enabled
#Enable Sandboxing for Windows Defender
Write-Host " -Enabling Sandboxing for Windows Defender"
setx /M MP_FORCE_USE_SANDBOX 1 | Out-Null
#Set cloud block level to 'High'
Write-Host " -Setting cloud block level to 'High'"
Set-MpPreference -CloudBlockLevel High
#Set cloud block timeout to 1 minute
Write-Host " -Setting cloud block timeout to 1 minute"
Set-MpPreference -CloudExtendedTimeout 50
#Schedule signature updates every 8 hours
Write-Host " -Scheduling signature updates every 8 hours"
Set-MpPreference -SignatureUpdateInterval 8
#Randomize Scheduled Task Times
Write-Host " -Randomizing Scheduled Task Times"
Set-MpPreference -RandomizeScheduleTaskTimes $true

Write-Host "Disabling Account Prompts"
# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
If (!(Test-Path -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Security Health\State\AccountProtection_MicrosoftAccount_Disconnected")) {
    New-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType "DWORD" -Value "1" -Force
}Else {
    New-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType "DWORD" -Value "1" -Force
}

Write-Host "Enabling Cloud-delivered Protections"
#Enable Cloud-delivered Protections
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

Write-Host "Enabling... Windows Defender Attack Surface Reduction Rules"
#https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-attack-surface-reduction
#https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
Write-Host " -Block executable content from email client and webmail"
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block all Office applications from creating child processes"
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Office applications from creating executable content"
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Office applications from injecting code into other processes"
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block JavaScript or VBScript from launching downloaded executable content"
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block execution of potentially obfuscated scripts"
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Win32 API calls from Office macros"
Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block credential stealing from the Windows local security authority subsystem"
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block persistence through WMI event subscription"
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block process creations originating from PSExec and WMI commands"
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block untrusted and unsigned processes that run from USB"
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Office communication application from creating child processes"
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Adobe Reader from creating child processes"
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block persistence through WMI event subscription"
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block abuse of exploited vulnerable signed drivers"
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Use advanced protection against ransomware"
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled

Write-Host "Enabling... Windows Defender Group Policy Settings"
.\Files\LGPO\LGPO.exe /g .\Files\GPO\

Write-Host "Updating Signatures..."
#Update Signatures
# cd $env:programfiles"\Windows Defender"
# .\MpCmdRun.exe -removedefinitions -dynamicsignatures
# .\MpCmdRun.exe -SignatureUpdate
Update-MpSignature -UpdateSource MicrosoftUpdateServer
Update-MpSignature -UpdateSource MMPC

Write-Host "Printting Current Windows Defender Configuration"
# Print Historic Detections
Get-MpComputerStatus ; Get-MpPreference ; Get-MpThreat ; Get-MpThreatDetection

Write-Host "Starting Full Scan and removing any known threats..."
#Start Virus Scan
Start-MpScan -ScanType FullScan

#Remove Active Threats From System
Remove-MpThreat

Write-Host "Windows Defender a ete optimiser avec succès !" -ForegroundColor Green

############################################################################################################
# Optimize Windows 
############################################################################################################
Write-Host "L'optimisation commence..." -ForegroundColor Yellow

function Checks{
    if(!($WindowsVersion -match "Microsoft Windows 11")) {
        Write-Warning " No supported operating system! Windows 11 required"
        Write-Warning " The script will be closed in 20 seconds"
        Start-Sleep 20;exit
    }
}

function WindowsTweaks_Services {
    $services = @(
    "WpcMonSvc",
    "SharedRealitySvc",
    "Fax",
    "autotimesvc",
    "wisvc",
    "SDRSVC",
    "MixedRealityOpenXRSvc",
    "WalletService",
    "SmsRouter",
    "SharedAccess",
    "MapsBroker",
    "PhoneSvc",
    "ScDeviceEnum",
    "TabletInputService",
    "icssvc",
    "edgeupdatem",
    "edgeupdate",
    "MicrosoftEdgeElevationService",
    "RetailDemo",
    "MessagingService",
    "PimIndexMaintenanceSvc",
    "OneSyncSvc",
    "UnistoreSvc",
    "DiagTrack",
    "dmwappushservice",
    "diagnosticshub.standardcollector.service",
    "diagsvc",
    "WerSvc",
    "wercplsupport",

    "Spouleur d'impresssion",
    "ClickToRunSvc",
    "OneSyncSvc_184354",
    "MapsBroker")
    foreach ($service in $services){
    Stop-Service $service
    Set-Service $service -StartupType Disabled}
}

function WindowsTweaks_Registry{
    # MarkC Mouse Acceleration Fix
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseXCurve" ([byte[]](0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xCC, 0x0C, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x66, 0x26,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00))
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseYCurve" ([byte[]](0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00))
    New-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\Mouse" -Name "MouseSensitivity" -Type "DWORD" -Value 10 -Force
    New-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\Mouse" -Name "MouseSpeed" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\Mouse" -Name "MouseTrails" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\Mouse" -Name "MouseThreshold1" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\Mouse" -Name "MouseThreshold2" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKEY_CURRENT_USER\Control Panel\Desktop" -Name "MenuShowDelay" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force 
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Type "DWORD" -Value 00000005 -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Name "NetworkThrottlingIndex" -Type "DWORD" -Value 268435455 -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Name "SystemResponsiveness" -Type "DWORD" -Value 00000000 -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type "DWORD" -Value 00000006 -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High" -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Value "High" -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force 
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 4 -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWORD" -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type "DWORD" -Value 0 -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force 
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Type "DWORD" -Value 1 -Force
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Value "Deny" -Force
}
        
function WindowsTweaks_Tasks{
    Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask -ErrorAction SilentlyContinue
    schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE 
    schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE 
}

function WindowsTweaks_Features{
    $features = @(
    "TFTP",
    "TelnetClient",
    "WCF-TCP-PortSharing45",
    "Microsoft-Hyper-V-All",
    "Microsoft-Hyper-V-Management-Clients",
    "Microsoft-Hyper-V-Tools-All",
    "Microsoft-Hyper-V-Management-PowerShell")
    foreach ($feature in $features) {
        dism /Online /Disable-Feature /FeatureName:$feature /NoRestart
    }
}
            
function WindowsTweaks_Index{
    Label C: Windows
    $drives = @('C:', 'D:', 'E:', 'F:', 'G:')
    foreach ($drive in $drives) {
        Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$drive'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null
    }
}

function TakeOwnership{
    New-Item "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\TakeOwnership" -force -ea SilentlyContinue
    New-Item "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\TakeOwnership\command" -force -ea SilentlyContinue
    New-Item "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\TakeOwnership" -force -ea SilentlyContinue
    New-Item "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -force -ea SilentlyContinue
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\TakeOwnership' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force| -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'Position' -Value 'middle' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\TakeOwnership\command' -Name '(default)' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F /c /l'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\TakeOwnership\command' -Name 'IsolatedCommand' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F /c /l'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'AppliesTo' -Value 'NOT (System.ItemPathDisplay:="C:\Users" OR System.ItemPathDisplay:="C:\ProgramData" OR System.ItemPathDisplay:="C:\Windows" OR System.ItemPathDisplay:="C:\Windows\System32" OR System.ItemPathDisplay:="C:\Program Files" OR System.ItemPathDisplay:="C:\Program Files (x86)")' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'Position' -Value 'middle' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\TakeOwnership\command' -Name '(default)' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant *S-1-3-4:F /c /l /q'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\TakeOwnership\command' -Name 'IsolatedCommand' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant *S-1-3-4:F /c /l /q'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
}
                
function SophiaScript{
    Clear-Host
    iF($WindowsVersion -match "Microsoft Windows 11") {
        Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/6.3.2/Sophia.Script.for.Windows.11.v6.3.2.zip" -Destination $env:temp\Sophia.zip
        Expand-Archive $env:temp\Sophia.zip $env:temp -force
        Move-Item -Path $env:temp\"Sophia_Script*" -Destination $ScriptFolder\Sophia_Script\
        Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/main/config/Sophia_Win11.ps1" -Destination "$ScriptFolder\Sophia_Script\Sophia.ps1"
    }
    Powershell.exe -executionpolicy Bypass $ScriptFolder\Sophia_Script\Sophia.ps1
    else { 
        Write-Host "Can't start SophiaScript"
    }
}

function ooShutup{
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/main/config/ooshutup10.cfg" -Destination "$ScriptFolder\ooshutup10.cfg"
    Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination $ScriptFolder\OOSU10.exe
    Set-Location $ScriptFolder
    .\OOSU10.exe ooshutup10.cfg /quiet
}

function Autoruns{
    Start-BitsTransfer -Source "https://download.sysinternals.com/files/Autoruns.zip" -Destination $env:temp\Autoruns.zip
    Expand-Archive $env:temp\Autoruns.zip  $env:temp
    Start-Process $env:temp\Autoruns64.exe 
}

function WindowsCleanup{
    Clear-Host
    gpupdate.exe /force 
    ipconfig /flushdns
    Start-Process -FilePath "cmd.exe"  -ArgumentList '/c "%windir%\system32\rundll32.exe advapi32.dll,ProcessIdleTasks'
    $Key = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches
    ForEach($result in $Key){
        if($result.name -eq "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\DownloadsFolder"){

        }Else{
        $Regkey = 'HKLM:' + $result.Name.Substring( 18 )
        New-ItemProperty -Path $Regkey -Name 'StateFlags0001' -Value 2 -PropertyType DWORD -Force -EA 0 | Out-Null
        }
    }
}
          
function Runtime{
    winget source update | Out-Null
    winget install --id=Microsoft.dotNetFramework --exact --accept-source-agreements 
    IF(!($InstalledSoftware -Contains "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.34.31931")){winget install --id=Microsoft.VCRedist.2015+.x64 --exact --accept-source-agreements}
    IF(!($InstalledSoftware -Contains "Microsoft Windows Desktop Runtime - 6.0.14 (x64)")){winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x64 --exact --accept-source-agreements}
    IF(!($InstalledSoftware -Contains "Microsoft Windows Desktop Runtime - 7.0.3 (x64)")){winget install --id=Microsoft.DotNet.DesktopRuntime.7 --architecture x64 --exact --accept-source-agreements}
    winget install --id=Microsoft.DirectX --exact --accept-source-agreements
}
    
function Process_Lasso{
    Start-BitsTransfer -Source "https://dl.bitsum.com/files/processlassosetup64.exe" -Destination $env:temp\ProcesslassoSetup64.exe
    Start-Process -FilePath "$env:temp\ProcesslassoSetup64.exe" -ArgumentList "/S /language=French"
}

Checks
WindowsTweaks_Services
WindowsTweaks_Registry
WindowsTweaks_Tasks
WindowsTweaks_Features
WindowsTweaks_Index
TakeOwnership
SophiaScript
ooShutup
Autoruns
WindowsCleanup
Runtime
Process_Lasso

##############################################################################################################
# Nettoyage du système
##############################################################################################################
Write-Host "Le nettoyage du disque commence..." -ForegroundColor Yellow

#Suppression des fichiers temporaires
$Key = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches
ForEach($result in $Key) {
    If($result.name -eq "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\DownloadsFolder"){

    }Else{
    $Regkey = 'HKLM:' + $result.Name.Substring( 18 )
    New-ItemProperty -Path $Regkey -Name 'StateFlags0001' -Value 2 -PropertyType DWORD -Force -EA 0 | Out-Null}
}

sfc /SCANNOW
Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore /NoRestart
Dism.exe /Online /Cleanup-Image /spsuperseded /NoRestart
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /NoRestart
Clear-BCCache -Force -ErrorAction SilentlyContinue

$paths = @(
"$env:temp",
"$env:windir\Temp",
"$env:windir\Prefetch",
"$env:SystemRoot\SoftwareDistribution\Download",
"$env:ProgramData\Microsoft\Windows\RetailDemo",
"$env:LOCALAPPDATA\AMD",
"$env:windir/../AMD/",
"$env:LOCALAPPDATA\NVIDIA\DXCache",
"$env:LOCALAPPDATA\NVIDIA\GLCache",
"$env:APPDATA\..\locallow\Intel\ShaderCache",
"$env:LOCALAPPDATA\CrashDumps",
"$env:APPDATA\..\locallow\AMD",
"$env:windir\..\MSOCache")
foreach ($path in $paths) {
    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse
}
lodctr /r
lodctr /r


Start-Process cleanmgr.exe /sagerun:1 -Wait
Write-Warning "Le system a été nettoyé avec succès !" -ForegroundColor Green

function Reboot{
    Write-Warning "Le system a été optimisé avec succès et vas redemarer dans 20 secondes!" -ForegroundColor Green
    Start-Sleep 20
    Restart-Computer
}
Reboot #rebbot le system