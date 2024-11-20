##########################################################################################
#Starting the tool
##########################################################################################

#Window Name
$Host.UI.RawUI.WindowTitle = "Hardening_Windows $([char]0x00A9)" 
vssadmin delete shadows /all /quiet | Out-Null

#Creating a restore point
Enable-ComputerRestore -Drive "C:\"
Checkpoint-Computer -Description "RestorePointBeforeHardening"


##########################################################################################
#Setting up Windows Defender

#https://www.powershellgallery.com/packages/WindowsDefender_InternalEvaluationSetting
#https://social.technet.microsoft.com/wiki/contents/articles/52251.manage-windows-defender-using-powershell.aspx
#https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps
#https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-attack-surface-reduction
#https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
##########################################################################################
Write-Host "Windows Defender setup begins..." -ForegroundColor Yellow

if ((Get-Location).Path -NE $PSScriptRoot) { Set-Location $PSScriptRoot } #Set Directory to PSScriptRoot

Write-Host "- Enabling real-time monitoring"
Set-MpPreference -DisableRealtimeMonitoring $false
Write-Host "- Disabling sample submission"
Set-MpPreference -SubmitSamplesConsent Never
Write-Host "- Enabling checking signatures before scanning"
Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
Write-Host "- Enabling behavior monitoring"
Set-MpPreference -DisableBehaviorMonitoring $false
Write-Host "- Enabling IOAV protection"
Set-MpPreference -DisableIOAVProtection $false
Write-Host "- Enabling script scanning"
Set-MpPreference -DisableScriptScanning $false
Write-Host "- Enabling removable drive scanning"
Set-MpPreference -DisableRemovableDriveScanning $false
Write-Host "- Enabling Block at first sight"
Set-MpPreference -DisableBlockAtFirstSeen $false
Write-Host "- Enabling potentially unwanted apps"
Set-MpPreference -PUAProtection 1
Write-Host "- Enabling archive scanning"
Set-MpPreference -DisableArchiveScanning $false
Write-Host "- Enabling email scanning"
Set-MpPreference -DisableEmailScanning $false
Write-Host "- Enabling File Hash Computation"
Set-MpPreference -EnableFileHashComputation $true
Write-Host "- Enabling Intrusion Prevention System"
Set-MpPreference -DisableIntrusionPreventionSystem $false
Write-Host "- Enabling TLS Parsing"
Set-MpPreference -DisableTlsParsing $false
Write-Host "- Enabling SSH Parsing"
Set-MpPreference -DisableSshParsing $false
Write-Host "- Enabling DNS Parsing"
Set-MpPreference -DisableDnsParsing $false
Set-MpPreference -DisableDnsOverTcpParsing $false
Write-Host "- Enabling DNS Sinkhole"
Set-MpPreference -EnableDnsSinkhole $true
Write-Host "- Enabling Controlled Folder Access and setting to block mode"
Set-MpPreference -EnableControlledFolderAccess Enabled
Write-Host "- Enabling Network Protection and setting to block mode"
Set-MpPreference -EnableNetworkProtection Enabled
Write-Host "- Enabling Sandboxing for Windows Defender"
setx /M MP_FORCE_USE_SANDBOX 1 | Out-Null
Write-Host "- Setting cloud block level to 'High'"
Set-MpPreference -CloudBlockLevel High
Write-Host "- Setting cloud block timeout to 1 minute"
Set-MpPreference -CloudExtendedTimeout 50
Write-Host "- Scheduling signature updates every 8 hours"
Set-MpPreference -SignatureUpdateInterval 8

Write-Host "Disabling Account Prompts" #Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
If (!(Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Security Health\State\AccountProtection_MicrosoftAccount_Disconnected")) { 
}Else {
    New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -PropertyType "DWORD" -Value "1" -Force
}

Write-Host "Enabling Cloud-delivered Protections"
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

Write-Host "Enabling... Windows Defender Attack Surface Reduction Rules"
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
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block process creations originating from PSExec and WMI commands"
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block untrusted and unsigned processes that run from USB"
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Office communication application from creating child processes"
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block Adobe Reader from creating child processes"
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Block abuse of exploited vulnerable signed drivers"
Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
Write-Host " -Use advanced protection against ransomware"
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled

Write-Host "Printting Current Windows Defender Configuration"
Get-MpComputerStatus ; Get-MpPreference ; Get-MpThreat ; Get-MpThreatDetection

Write-Host "Windows Defender has been optimized successfully!" -ForegroundColor Green

############################################################################################################
#Optimizing Windows 
############################################################################################################
Write-Host "Windows optimization begins..." -ForegroundColor Yellow


function WindowsTweaks_Services {
    $servicesDisable = @(
    "WpcMonSvc",
    "SharedRealitySvc",
    "Fax",
    "autotimesvc",
    "wisvc",
    "SDRSVC",
    "MixedRealityOpenXRSvc",
    "WalletService",
    "SmsRouter",
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
    "dmwappushservice",
    "diagnosticshub.standardcollector.service",
    "diagsvc",
    "WerSvc",
    "wercplsupport",

    "wlidsvc",
    "NcdAutoSetup",
    "DataCollectionPublishingService",
    "SSDPSRV",
    "dmwapphushservice",
    "DiagTrack",
    "Browser",
    "HomeGroupProvider",
    "p2pimsvc",
    "XblAuthManager",
    "RasAuto",
    "RasMan",
    "p2psvc",
    "upnphost",
    "fdPHost",
    "XblGameSave",
    "ltdsvc",
    "SharedAccess",
    "PNRPsvc",
    "FDResPub",
    "RemoteRegistry",
    "RemoteAccess",
    "WlanSvc",
    "WwanSvc",
    "WinHttpAutoProxySvc",
    "retaildemo",
    "lfsvc",
    "blthserv",
    "AJRouter",
    "WMPNetworkSvc",
    "WSService",
    "wcncsvc",

    "ClickToRunSvc",
    "OneSyncSvc_184354",
    "MapsBroker")
    foreach ($serviceDisable in $servicesDisable){
        $StopService = Get-Service -Name $serviceDisable -ErrorAction SilentlyContinue #Obtain the service object

        if ($serviceDisable.Length -gt 0) { #Check if the service exists

            if ($StopService.Status -ne 'Running'){ #Check if the service is running
            Stop-Service $serviceDisable
            Set-Service $serviceDisable -StartupType Disabled
            }
            else{
                Write-Host "The service $serviceDisable is already disabled"
            }
        }
       else {
        Write-Host "The service $serviceDisable does not exist"
        }
    }

    $servicesEnable = @(
        "AppIDSvc",
        "gpsvc",
        "EventLog",
        "Netlogon",
        "MpsSvc")
    foreach ($serviceEnable in $servicesEnable){
        $StartService = Get-Service -Name $serviceEnable -ErrorAction SilentlyContinue #Obtain the service object

        if ($serviceDisable.Length -gt 0) { #Check if the service exists

            if ($StartService.Status -ne 'Stopped'){ #Check if the service is stopped
            Set-Service $serviceEnable -StartupType Automatic
            }
            else{
                Write-Host "The service $serviceDisable is already active"
            }
        }
        else {
        Write-Host "The service $serviceDisable does not exist"
        }
    }
}

function WindowsTweaks{
    #Disallow Kerberos from using DES or RC4
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
    #Encrypt and sign outgoing traffic over secure channel if possible
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
    #Activate the intelligent screen (SmartScreen)
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f
    #Activate "DontDisplayNetworkSelectionUI"
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f
    #Discover extensions and hidden files
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
    #Disable autoplay from all disks
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
    #Blocks download optimization from other devices on the network
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\" /v DODownloadMode /t REG_DWORD /d 0 /f
}

function WindowsTweaks_Registry{
    #MarkC Mouse Acceleration Fix
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseXCurve" ([byte[]](0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xCC, 0x0C, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x66, 0x26,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00))
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseYCurve" ([byte[]](0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00))
    New-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Mouse" -Name "MouseSensitivity" -Value 10 -Force
    New-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Mouse" -Name "MouseSpeed" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Mouse" -Name "MouseTrails" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Mouse" -Name "MouseThreshold1" -Value 0 -Force
    New-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Mouse" -Name "MouseThreshold2" -Value 0 -Force
    Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0 -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Value 4 -Force 
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Value 00000005 -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Name "NetworkThrottlingIndex" -Value 268435455 -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Name "SystemResponsiveness" -Value 00000000 -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 00000006 -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High" -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Value "High" -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Value 4 -Force 
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Value 4 -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Value 0 -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Value 1 -Force
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Value "Deny" -Force
}
        
function WindowsTweaks_Tasks{
    Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
    Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask -ErrorAction SilentlyContinue
    schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
    schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
    schtasks /change /TN "Microsoft\Windows\Autochk\Proxy" /DISABLE
    schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
    schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
    schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /DISABLE
    schtasks /change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
    schtasks /change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnoticDataCollector" /DISABLE
    schtasks /change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /DISABLE
    schtasks /change /TN "Microsoft\Windows\WPD\SqmUpload_S-1-5-21-3244633361-4016055161-2943779436-1000" /DISABLE
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

function WindowsCleanup{
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

function ApplicationDisabling {
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\explorer" /f
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\explorer" /f /v DisallowRun /t REG_DWORD /d 1
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\explorer\DisallowRun" /f

    $ApplicationsDisabling = @(
        "bing.exe",
        "messages.exe",
        "solitaire collection.exe",
        "contacts.exe",
        "skype.exe",
        "xbox.exe"
    )
    foreach ($ApplicationDisabling in $ApplicationsDisabling){
        reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\explorer\DisallowRun" /v $ApplicationDisabling /t REG_SZ /d $ApplicationDisabling /f
    }
    Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.Getstarted* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.Messaging* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.OneConnect* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.Print3D* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.Wallet* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *microsoft.windowscommunicationsapps* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.WindowsFeedbackHub* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.WindowsSoundRecorder* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.WindowsFeedback* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Windows.ContactSupport* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *PandoraMedia* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *AdobeSystemIncorporated. AdobePhotoshop* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Duolingo* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.BingNews* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *ActiproSoftware* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *EclipseManager* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *SpotifyAB.SpotifyMusic* -AllUsers | Remove-AppxPackage
    Get-AppxPackage *king.com.* -AllUsers | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online
    Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.GetHelp'} | Remove-AppxProvisionedPackage -Online
    Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Getstarted'} | Remove-AppxProvisionedPackage -Online
    Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.SkypeApp'} | Remove-AppxProvisionedPackage -Online
    Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'microsoft.windowscommunicationsapps'} | Remove-AppxProvisionedPackage -Online
    Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsFeedbackHub'} | Remove-AppxProvisionedPackage -Online
    Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online
    wmic /interactive:off product where "name like 'Adobe Air%' and version like'%'" call uninstall
    wmic /interactive:off product where "name like 'Adobe Flash%' and version like'%'" call uninstall
    wmic /interactive:off product where "name like 'Java%' and version like'%'" call uninstall
    wmic /interactive:off product where "name like 'Ask Part%' and version like'%'" call uninstall
    wmic /interactive:off product where "name like 'searchAssistant%' and version like'%'" call uninstall
    wmic /interactive:off product where "name like 'Weatherbug%' and version like'%'" call uninstall
    wmic /interactive:off product where "name like 'ShopAtHome%' and version like'%'" call uninstall
}

function ServiceAllow {
    $ServicesAllow = @(
        "appointments",
        "phoneCallHistory"
        "contacts",
        "email",
        "location",
        "chat",
        "userAccountInformation"
    )
    foreach ($ServiceAllow in $ServicesAllow){
        Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$ServiceAllow -Name Value -Value Allow
    }
}

function TLS_SSLTweak{
    #Disable toggle user control on Insider preview builds
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds" -Name AllowBuildPreview -Value 0
    #Disable comment notification
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" -Name DoNotShowFeedbackNotifications -Value 1
    #Disable the Inventory Collector
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat" -Name DisableInventory -Value 1
    #Disable Microsoft Consumer Experiences
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Value 1
    #Do not show Windows tips
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableSoftLanding -Value 1
    #Block a Windows application from sharing application data between users
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" -Name AllowSharedLocalAppData -Value 0
    #Disable location
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name DisableLocation -Value 1
    #Disable location script
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name DisableLocationScripting -Value 1
    #Allow Microsoft accounts to be optional
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name MSAOptional -Value 1
    #Block basic authentication
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" -Name AllowBasic -Value 0
    #Block unencrypted traffic
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" -Name AllowUnencryptedTraffic -Value 0
    #Do not allow Digest authentication
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" -Name AllowDigest -Value 1
    #Do not allow negotiation authentication
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" -Name AllowNegotiate -Value 1
    #Disable remote server management via WinRM
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" -Name AllowAutoConfig -Value 0
    #Disable HTTP compatibility listener
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" -Name HttpCompatibilityListener -Value 0
    #Disable HTTPS Compatibility Listener
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" -Name HttpsCompatibilityListener -Value 0
    #Disable WinRM to store RunAs credentials
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" -Name DisableRunAs -Value 1
    #Enable Kerberos authentication
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client" -Name AllowKerberos -Value 0
    #Disable CredSSP Authentication
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client" -Name AllowCredSSP -Value 0
    #Generate security audits
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -Value 1
    #Disable automatic root certificate update
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SystemCertificates\AuthRoot" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SystemCertificates\AuthRoot" -Name DisableRootAutoUpdate -Value 1
    #Disable "Events.asp" links from the Event Viewer
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EventViewer" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EventViewer" -Name MicrosoftEventVwrDisableLinks -Value 1
    #Disable “Did you know?” content from Help and Support Center
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\PCHealth\HelpSvc" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\PCHealth\HelpSvc" -Name Headlines -Value 1
    #Disable Microsoft Knowledge Base search in Help and Support Center
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\PCHealth\HelpSvc" -Name MicrosoftKBSearch -Value 1
    #Disable Internet Connection Assistant if the connection URL refers to Microsoft.com
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Internet Connection Wizard" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Internet Connection Wizard" -Name ExitOnMSICW -Value 1
    #Disable registration if sign-in URL refers to Microsoft.com
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Registration Wizard Control" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Registration Wizard Control" -Name NoRegistration -Value 1
    #Disable Search Assistant content file updates
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SearchCompanion" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SearchCompanion" -Name DisableContentFileUpdates -Value 1
    #Disable Internet File Association Service
    reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f
    Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoInternetOpenWith -Value 1
    #Disable active Windows Network Connectivity Status Indicator tests
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name NoActiveProbe -Value 1
    #Disable Help Ratings
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Assistance\Client\1.0" /f
    Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Assistance\Client\1.0" -Name NoExplicitFeedback -Value 1
    #Disable the Help Enhancement Program
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SQMClient\Windows" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SQMClient\Windows" -Name CEIPEnable -Value 1
    #Disable Windows Online
    Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Assistance\Client\1.0" -Name NoOnlineAssist -Value 1
    #Disabling printing via HTTP
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers" -Name DisableHTTPPrinting -Value 1
    #Disable downloading printer drivers via HTTP
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers" -Name DisableWebPnPDownload -Value 1
    #Disable Internet Downloading for Website Publishing and Online Ordering Wizards via the Internet
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoWebServices -Value 1
    #Disable the Order Photos option from Image Management
    Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoOnlinePrintsWizard -Value 1
    #Disable the Publish to Web option in File Management
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoPublishingWizard -Value 1
    #Disable Windows Messenger Service Improvement Program
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client" -Name CEIP -Value 1
    #Disable sharing of handwriting customization data
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TabletPC" /f
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\TabletPC" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TabletPC" -Name PreventHandwritingDataSharing -Value 1
    Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\TabletPC" -Name PreventHandwritingDataSharing -Value 1
    #Enable enhanced security level for channel binding tokens
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service" -Name CBTHardeningLevelStatus -Value 1
    #Prevent the computer from joining a homegroup
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HomeGroup" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HomeGroup" -Name DisableHomeGroup -Value 1
    #Require trusted path for credential entry
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name EnableSecureCredentialPrompting -Value 1
    #Disable or enable the security key sequence (SAS, Secure Attention Sequence)
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name SoftwareSASGeneration -Value 3 #Ergonomics services and applications
    #Disable Windows Error Reporting
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Value 1
    #Disable Cortana
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Value 0
    #Disable search and allow Cortana to use location
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowSearchToUseLocation -Value 0
    #Do not allow saving of passwords
    reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /f
    Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name DisablePasswordSaving -Value 1
    #Do not allow drive redirection
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fDisableCdm -Value 1
    #Require secure RPC communications
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fEncryptRPCTraffic -Value 1
    #Disable autorun for devices other than those in the volume
    Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoAutoplayfornonVolume -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoAutoplayfornonVolume -Value 1
    #Join Microsoft MAPS (Online Threat Response Community)
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" -Name SpynetReporting -Value 2
    #Scan all downloaded files and attachments
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableIOAVProtection -Value 0
    #Enable real-time protection
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableRealtimeMonitoring -Value 0
    #Do not always install applications with elevated rights
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer" /f
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" /f
    Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -Value 0
    #Configuring the Automatic Updates service
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Value 3 #Automatic download and installation notification
    #WDigest Authentication (disabling may require KB2871997)
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 0
    #MSS: (DisableSavePassword) Prevent the dial-up password from being saved
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -Name DisableSavePassword -Value 1
    #MSS: (EnableICMPRedirect) Prevent ICMP redirects to override OSPF generated routes
    reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" -Name EnableICMPRedirect -Value 0
    #MSS: (Hidden) Hide Computer From the Browse List (not recommended except for highly secure environments)
    reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Lanmanserver\Parameters" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Lanmanserver\Parameters" -Name Hidden -Value 1
    #MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers
    reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters" -Name NoNameReleaseOnDemand -Value 1
    #MSS: (PerformRouterDiscovery) Prevent IRDP to detect and configure Default Gateway addresses (could lead to DoS)
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" -Name PerformRouterDiscovery -Value 0
    #MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" -Name SafeDllSearchMode -Value 1
    #MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" -Name TcpMaxDataRetransmissions -Value 3
    #MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)
    reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters" -Name TcpMaxDataRetransmissions -Value 3
    #MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" -Name DisableIPSourceRouting -Value 2 #Highest protection, source routing is completely disabled
    #MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters" -Name DisableIPSourceRouting -Value 2 #Highest protection, source routing is completely disabled
    #MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" -Name KeepAliveTime -Value 300000 #300000 or 5 minutes (recommended)
    #Disable SSL 2.0
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0" /f /v Server /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0" /f /v Client /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name DisabledByDefault -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name DisabledByDefault -Value 1
    #Disable SSL 3.0
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0" /f /v Server /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0" /f /v Client /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name DisabledByDefault -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name DisabledByDefault -Value 1
    #Disable TLS 1.0
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0" /f /v Server /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0" /f /v Client /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name DisabledByDefault -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name DisabledByDefault -Value 1
    #Disable TLS 1.1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1" /f /v Server /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1" /f /v Client /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name DisabledByDefault -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name DisabledByDefault -Value 1
    #Disable TLS 1.2
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2" /f /v Server /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2" /f /v Client /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name DisabledByDefault -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name Enabled -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name DisabledByDefault -Value 1
    #Disable TLS 1.3
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3" /f /v Server /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3" /f /v Client /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name Enabled -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name DisabledByDefault -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name Enabled -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name DisabledByDefault -Value 0
    #OCSP stapling
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v EnableOcspStaplingForSni /t REG_DWORD /d 1 /f
    #Enabling Strong Authentication for .NET Framework 3.5
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
    #Enabling Strong Authentication for .NET Framework 4.0/4.5.x
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
    #Prevent the lock screen camera from being activated
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization" -Name NoLockScreenCamera -Value 1
    #Disable Microsoft Peer-to-Peer Network Services
    reg add "HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Peernet" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Peernet" -Name Disabled -Value 1
    #Disable multicast name resolution
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 1
    #Disable intelligent multihomed name resolution
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\DNSClient" -Name DisableSmartNameResolution -Value 1
    #Disallow the installation and configuration of a network bridge on your DNS domain network
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Network Connections" -Name NC_AllowNetBridge_NLA -Value 1 
    #Disable Link Layer Topology Discovery Mapper Input/Output Driver
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD" -Name EnableLLTDIO -Value 0
    #Disable the responder driver (RSPNDR)
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LLTD" -Name EnableRspndr -Value 0
    #Disable connection to non-domain networks when connecting to a domain-authenticated network
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name fBlockNonDomain -Value 1
    #Order of SSL Cipher Suites
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name Functions -Type REG_SZ -Value TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_DHE_DSS_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_RC4_128_MD5,SSL_CK_RC4_128_WITH_MD5,SSL_CK_DES_192_EDE3_CBC_WITH_MD5,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA
    #Enable ISATAP
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name ISATAP_State -Value Enabled
    #Activate Teredo
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name Teredo_State -Value Client
    #Enable IP-HTTPS
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface" -Name IPHTTPS_ClientState -Value 2
    #Prevent Windows from automatically connecting to suggested open hotspots, networks shared by contacts, and hotspots offering paid services
    reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\wcmsvc\wifinetworkmanager\config" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\wcmsvc\wifinetworkmanager\config" -Name AutoConnectAllowedOEM -Value 0
    #Disable insecure guest logins
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation" -Name AllowInsecureGuestAuth -Value 0
    #Block access to Windows Connect Now Assistants
    reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WCN\UI" /f
    Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WCN\UI" -Name DisableWcnUi -Value 1
    #Configuring Wireless Settings Using Windows Connect Now
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrars" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrars" -Name EnableRegistrars -Value 0
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrars" -Name DisableUPnPRegistrar -Value 0 #Disable the ability to configure using Windows Connect Now over Ethernet (UPnP)
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrars" -Name DisableInBand802DOT11Registrar -Value 0 #Disable the ability to configure using Windows Connect Now (WCN) on WLAN 802.11
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WCN\Registrars" -Name DisableFlashConfigRegistrar -Value 0 #Disable the ability to configure using a USB flash drive
    #CD and DVD: deny execution access
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}" -Name Deny_Execute -Value 1
    #Floppy drives: deny execute access
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}" -Name Deny_Execute -Value 1
    #Removable disks: deny execution access
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" -Name Deny_Execute -Value 1
    #Tape drives: deny execution access
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}" -Name Deny_Execute -Value 1
    #Enable Client Authentication RPC Endpoint Mapper
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc" -Name EnableAuthEpResolution -Value 1
    #Limit unauthenticated RPC clients
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc" -Name RestrictRemoteClients -Value 1 #Authenticate
    #Configure requested remote assistance
    reg add "HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Windows NT\Terminal Services" -Name fAllowFullControl -Value 0 #Only allow advisors to see the computer
    #Ask for password when computer wakes from sleep (on AC power)
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name ACSettingIndex -Value 1
    #Ask for password when computer wakes from sleep (on battery)
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" -Name DCSettingIndex -Value 1
    #Do not allow sleep states (S1-S3) when the computer is sleeping (on AC power)
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name ACSettingIndex -Value 0 #disable
    #Do not allow sleep states (S1-S3) when the computer is sleeping (on battery)
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name DCSettingIndex -Value 0 #disable
    #Boot Driver Initialization Strategy
    reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\EarlyLaunch" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies\EarlyLaunch" -Name DriverLoadPolicy -Value 1 #Good and unknown
    #Record events without blocking untrusted fonts
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions" -Name MitigationOptions_FontBocking -Value 3000000000000
    #Do not show animation on first login
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableFirstLogonAnimation -Value 0
    #Do not show network selection UI
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -Name DontDisplayNetworkSelectionUI -Value 1
    #Do not list users logged in on domain member computers
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -Name DontEnumerateConnectedUsers -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -Name EnumerateLocalUsers -Value 0
    #Disable app notifications on lock screen
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" -Name DisableLockScreenAppNotifications -Value 1
    #Disable Advertising ID
    reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AdvertisingInfo" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AdvertisingInfo" -Name DisabledByGroupPolicy -Value 1
    #Enable Virtualization-Based Security
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /f
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name EnableVirtualizationBasedSecurity -Value 1
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name RequirePlatformSecurityFeatures -Value 3 #Secure boot and DMA protection
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name HypervisorEnforcedCodeIntegrity -Value 1 #Virtualization-based protection of code integrity enabled with UEFI lockdown
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name LsaCfgFlags -Value 1 #Credential Guard configuration enabled with UEFI Lockdown
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name ConfigureSystemGuardLaunch -Value 1 #Secure boot
    #Disable toast notifications on lock screen
    reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /f
    Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoToastApplicationNotificationOnLockScreen -Value 1
}

function MicrosoftOfficeTweaks{
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\12.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\12.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\14.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\14.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\15.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\15.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\15.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\15.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\15.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\16.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\16.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Office\16.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Office\14.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Office\14.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Office\15.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Office\15.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Office\16.0\Word\Options" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Office\16.0\Word\Options\WordMail" /v DontUpdateLinks /t REG_DWORD /d 00000001 /f
}

function AdobeTweaks{
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Adobe\Acrobat Reader\DC\Installer" /v "DisableMaintenance" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bAcroSuppressUpsell" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bDisablePDFHandlerSwitching" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bDisableTrustedFolders" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bDisableTrustedSites" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bEnableFlash" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bProtectedMode" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "iFileAttachmentPerms" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "iProtectedView" /t REG_DWORD /d 2 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" /v "bAdobeSendPluginToggle" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" /v "iURLPerms" /t REG_DWORD /d 3 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" /v "iUnknownURLPerms" /t REG_DWORD /d 2 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bToggleAdobeDocumentServices" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bToggleAdobeSign" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bTogglePrefsSync" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bToggleWebConnectors" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" /v "bUpdater" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" /v "bDisableSharePointFeatures" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" /v "bDisableWebmail" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" /v "bShowWelcomeScreen" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" /v "DisableMaintenance" /t REG_DWORD /d 1 /f
}

function EdgeTweaks {
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"  /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "SitePerProcess" /t REG_DWORD /d "0x00000001" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "SSLVersionMin" /t REG_SZ /d "tls1.2^@" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "NativeMessagingUserLevelHosts" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0x00000001" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverride" /t REG_DWORD /d "0x00000001" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverrideForFiles" /t REG_DWORD /d "0x00000001" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "SSLErrorOverrideAllowed" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenPuaEnabled" /t REG_DWORD /d "0x00000001" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "AllowDeletingBrowserHistory" /t REG_DWORD /d "0x00000000" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist\1" /t REG_SZ /d "odfafepnkmbhccpbejgmiehpchacaeak" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist\1" /t REG_SZ /d "odfafepnkmbhccpbejgmiehpchacaeak" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak" /v "update_url" /t REG_SZ /d "https://edge.microsoft.com/extensionwebstorebase/v1/crx" /f
}

function GoogleChromeTweaks {
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "AlwaysOpenPdfExternally" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "BlockExternalExtensions" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d on /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d "1" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "RemoteAccessHostFirewallTraversal" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "DefaultPopupsSetting" /t REG_DWORD /d "33554432" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "DefaultGeolocationSetting" /t REG_DWORD /d "33554432" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "DefaultSearchProviderName" /t REG_SZ /d "Google Encrypted" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "DefaultSearchProviderSearchURL" /t REG_SZ /d "https://www.google.com/#q={searchTerms}" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "DefaultSearchProviderEnabled" /t REG_DWORD /d "16777216" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "AllowOutdatedPlugins" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "CloudPrintProxyEnabled" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "ImportSavedPasswords" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "IncognitoModeAvailability" /t REG_DWORD /d "16777216" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "EnableOnlineRevocationChecks" /t REG_DWORD /d "16777216" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "SavingBrowserHistoryDisabled" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "DefaultPluginsSetting" /t REG_DWORD /d "50331648" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "AllowDeletingBrowserHistory" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "PromptForDownloadLocation" /t REG_DWORD /d "16777216" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "DownloadRestrictions" /t REG_DWORD /d "33554432" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "AutoplayAllowed" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "SafeBrowsingExtendedReportingEnabled" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "DefaultWebUsbGuardSetting" /t REG_DWORD /d "33554432" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "EnableMediaRouter" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d "tls1.1" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "UrlKeyedAnonymizedDataCollectionEnabled" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "WebRtcEventLogCollectionAllowed" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "NetworkPredictionOptions" /t REG_DWORD /d "33554432" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "BrowserGuestModeEnabled" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v "ImportAutofillFormData" /t REG_DWORD /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\ExtensionInstallWhitelist" /v "1" /t REG_SZ /d "cjpalhdlnbpafiamejdnhcphjbkeiagm" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" /v "1" /t REG_SZ /d "cjpalhdlnbpafiamejdnhcphjbkeiagm" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\URLBlacklist" /v "1" /t REG_SZ /d "javascript://*" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Update" /v "AutoUpdateCheckPeriodMinutes" /t REG_DWORD /d "1613168640" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\Recommended" /v "SafeBrowsingProtectionLevel" /t REG_DWORD /d "2" /f
    #Enables isolation for each site
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v SitePerProcess /d "1" /t REG_DWORD /f >NUL 2>&1
    #Disable sending report after crash
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v MetricsReportingEnabled /d "0" /t REG_DWORD /f >NUL 2>&1
    #Disable old plugins
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v AllowOutdatedPlugins /d "0" /t REG_DWORD /f >NUL 2>&1
    #Enlarging the size of logs in Windows Event
    wevtutil sl Security /ms:1024000
    wevtutil sl Application /ms:1024000
    wevtutil sl System /ms:1024000
    wevtutil sl "Windows Powershell" /ms:1024000
    wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000
    #Saves command line data to the registry
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
    #Enable advanced settings
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
    #Enable connection to PowerShell
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
    #Enable log details
    Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
    Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
    Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
    Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
    Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
    Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
    Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
    Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
    Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
    Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
    Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
    Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
    #Applies limitations to Windows Analytics
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f
    #Applies Windows telemetry only in safe mode
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f
    #Turn off my location data
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v Location /t REG_SZ /d Deny /f
    #Prevent the start menu from providing internet information and using geolocation
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
    #Disable publication of user activity
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f
    #Disable ads with ID
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
    #Disable Windows GameDVR
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
    #Disable Microsoft Consumer Experience to prevent notifications and suggestions of apps to install
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
    reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
    #Disable websites access to the language list
    reg add "HKEY_USERS\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
    #Ban notifications on lock screen
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f
    #Enabling Anti-Spoofing for Face Recognition
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
    #Disable other cameras when screen is closed
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
    #Prevents Windows applications from recognizing speech when the screen is closed
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
}

function FirewallTweaks {
    NetSh Advfirewall set allprofiles state on
    #Enabling Firewall Connection
    netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
    netsh advfirewall set currentprofile logging maxfilesize 4096
    netsh advfirewall set currentprofile logging droppedconnections enable
    #Blocks all connections to the public profile
    netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
    #Enabling Windows Defender Network Protection
    powershell.exe Set-MpPreference -EnableNetworkProtection Enabled
    #Blocks connections when programs are not active
    netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block print.exe netconns" program="%systemroot%\system32\print.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block print.exe netconns" program="%systemroot%\SysWOW64\print.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
    netsh advfirewall firewall add rule name="block_Connect_in" dir=in program="%WINDIR%\SystemApps\Microsoft.PPIProjection_cw5n1h2txyewy\Receiver.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_Connect_out" dir=out program="%WINDIR%\SystemApps\Microsoft.PPIProjection_cw5n1h2txyewy\Receiver.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_ContactSupport_in" dir=in program="%WINDIR%\SystemApps\ContactSupport_cw5n1h2txyewy\ContactSupport.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_ContactSupport_out" dir=out program="%WINDIR%\SystemApps\ContactSupport_cw5n1h2txyewy\ContactSupport.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_Cortana_in" dir=in program="%WINDIR%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_Cortana_out" dir=out program="%WINDIR%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_DiagTrack_in" dir=in service="DiagTrack" action=block enable=yes
    netsh advfirewall firewall add rule name="block_DiagTrack_out" dir=out service="DiagTrack" action=block enable=yes
    netsh advfirewall firewall add rule name="block_dmwappushservice_in" dir=in service="dmwappushservice" action=block enable=yes
    netsh advfirewall firewall add rule name="block_dmwappushservice_out" dir=out service="dmwappushservice" action=block enable=yes
    netsh advfirewall firewall add rule name="block_FeedbackHub_in" dir=in program="%ProgramFiles%\WindowsApps\Microsoft.WindowsFeedbackHub_1.1708.2831.0_x64__8wekyb3d8bbwe\PilotshubApp.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_FeedbackHub_out" dir=out program="%ProgramFiles%\WindowsApps\Microsoft.WindowsFeedbackHub_1.1708.2831.0_x64__8wekyb3d8bbwe\PilotshubApp.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_OneNote_in" dir=in program="%ProgramFiles%\WindowsApps\Microsoft.Office.OneNote_17.8625.21151.0_x64__8wekyb3d8bbwe\onenoteim.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_OneNote_out" dir=out program="%ProgramFiles%\WindowsApps\Microsoft.Office.OneNote_17.8625.21151.0_x64__8wekyb3d8bbwe\onenoteim.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_Photos_in" dir=in program="%ProgramFiles%\WindowsApps\Microsoft.Windows.Photos_2017.39091.16340.0_x64__8wekyb3d8bbwe\Microsoft.Photos.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_Photos_out" dir=out program="%ProgramFiles%\WindowsApps\Microsoft.Windows.Photos_2017.39091.16340.0_x64__8wekyb3d8bbwe\Microsoft.Photos.exe" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RemoteRegistry_in" dir=in service="RemoteRegistry" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RemoteRegistry_out" dir=out service="RemoteRegistry" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RetailDemo_in" dir=in service="RetailDemo" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RetailDemo_out" dir=out service="RetailDemo" action=block enable=yes
    netsh advfirewall firewall add rule name="block_WMPNetworkSvc_in" dir=in service="WMPNetworkSvc" action=block enable=yes
    netsh advfirewall firewall add rule name="block_WMPNetworkSvc_out" dir=out service="WMPNetworkSvc" action=block enable=yes
    netsh advfirewall firewall add rule name="block_WSearch_in" dir=in service="WSearch" action=block enable=yes
    netsh advfirewall firewall add rule name="block_WSearch_out" dir=out service="WSearch" action=block enable=yes
}

##############################################################################################################
#System cleaning
##############################################################################################################
Write-Host "The system cleanup begins..." -ForegroundColor Yellow

lodctr /r

Start-Process cleanmgr.exe /sagerun:1 -Wait
Write-Host "The system has been cleaned up successfully!" -ForegroundColor Green

WindowsTweaks
WindowsTweaks_Services
WindowsTweaks_Registry
WindowsTweaks_Tasks
WindowsTweaks_Features
WindowsTweaks_Index
WindowsCleanup
Runtime
ApplicationDisabling
ServiceAllow
TLS_SSLTweak
MicrosoftOfficeTweaks
AdobeTweaks
GoogleChromeTweaks
FirewallTweaks

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
    if (Test-Path -Path $path) {
        Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse
    } 
    else {
        Write-Host "The path $path does not exist" -ForegroundColor Red
    }
}

sfc /SCANNOW
Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore /NoRestart
Dism.exe /Online /Cleanup-Image /spsuperseded /NoRestart
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /NoRestart
Clear-BCCache -ErrorAction SilentlyContinue

function Reboot{
    Write-Host "The system has been successfully optimized and will reboot in 20 seconds!" -ForegroundColor Green
    Start-Sleep 20
    Restart-Computer
}

Reboot