@echo off

:-------------------------------------
REM  :: Analyse les permissions
    IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

REM :: Si une erreur est detecte les autorisations admin sertont refusées
if '%errorlevel%' NEQ '0' (
    echo Demande des droits administrateurs...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

@echo off
setlocal
:PROMPT
SET /P AREYOUSURE=Etes vous sur de lancer le programme (Y/[N])? 
IF /I "%AREYOUSURE%" NEQ "Y" GOTO END

echo Lancement du programme

::#######################################################################
::#######################################################################
:: PowerShell
::#######################################################################
::#######################################################################
powershell.exe -ExecutionPolicy Bypass -File "Windows_Script.ps1"



::#######################################################################
::#######################################################################
:: Configuration des paramètres système
::#######################################################################
::#######################################################################


::#######################################################################
:: Activation et configuration des paramètres système
::#######################################################################
:: Desactivation du DNS multicast, smart mutli-homed resolution, netbios, powershellv2, installation des pilotes de l'imprimante et de l'impression par HTTP et redirection ICMP
:: Activation de l'UAC pour toujours notifier un changement dans le registre, chargement DLL sure (prevention contre le hijaccking DLL) et shell en mode protégé
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v DisableParallelAandAAAA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v IGMPLevel /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDLLSearchMode /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableHTTPPrinting /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v fMinimizeConnections /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
wmic /interactive:off nicconfig where (TcpipNetbiosOptions=0 OR TcpipNetbiosOptions=1) call SetTcpipNetbios 2
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -norestart
:: Interdire Kerberos d'utiliser DES ou RC4
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f
:: Encrypter et signer le trafique sortant par cannal sécurisé si possible
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f
:: Activer l'écran intélligent (SmartScreen)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f
:: Ameliore la signature des pilotes
BCDEDIT /set nointegritychecks OFF
:: Activation de l'écran de veille à partir de 15 minutes (900 secondes)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f
:: Activaton du mot de passe après veille quand l'appareil est sur batterie ou en charge
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f
:: Active le "DontDisplayNetworkSelectionUI"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DontDisplayNetworkSelectionUI /t REG_DWORD /d 1 /f
:: Decouvrir les extentions et fichier caché
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f


::#######################################################################
:: Paramétrage de Windows Update
::#######################################################################
:: Bloque l'optimisation de téléchargement depuis d'autres appareils du réseau
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\" /v DODownloadMode /t REG_DWORD /d 0 /f


::#######################################################################
:: Paramétrage de l'accès à distance
::#######################################################################
:: Désactivation de l'accès à distance
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
:: Exiger l'encryption RPC lors d'une connection à distance
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
:: Interdit la transmission de fichier à travers une connection à distance
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f


::#######################################################################
:: Paramétrage des lecteur media windows
::#######################################################################
:: Désactivation de la lecture automatique depuis tout les disques
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f


::#######################################################################
:: Paramètre de partage SMB
::#######################################################################
:: Activation de la signature optionel sur SMB
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -norestart
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
:: Force la signature SMB
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
:: Configuration de lsass.exe et désactivaton de wdigest
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f


::#######################################################################
:: Paramétrage de Windows RPC et WinRM
::#######################################################################
:: Stop WinRM
net stop WinRM
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
:: Désactive l'authentication WinRM Client Digiest
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v AllowDigest /t REG_DWORD /d 0 /f
:: Désactive l'utilisation du planificateur de tâches depuis un accès à distance
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" /v DisableRpcOverTcp /t REG_DWORD /d 1 /f
:: Désactive le RPC depuis un accès à distance
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v DisableRemoteScmEndpoints /t REG_DWORD /d 1 /f

::#######################################################################
:: Biometrie
::#######################################################################
:: Activation de l'anti-usurpation pour la reconnaissance faciale
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
:: Desactivation des autres camera quand l'écran est fermé
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
:: Empèche les applications Windows de reconnaissance vocale quand l'écran est fermé
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f


::#######################################################################
:: Windows Defender
::#######################################################################
:: Démarage de Windows Defender
sc start WinDefend
::Activation de Windows Defender sandboxing
setx /M MP_FORCE_USE_SANDBOX 1
:: Mise à jour de la signatures
"%ProgramFiles%"\"Windows Defender"\MpCmdRun.exe -SignatureUpdate
:: Activer la signature de Windows Defender contre les Programme Potentiellement Indésirable (PPI/PUA)
powershell.exe Set-MpPreference -PUAProtection enable
:: Activer le scan periodic
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows Defender" /v PassiveMode /t REG_DWORD /d 2 /f
:: Activer les fonctionalitées Cloud de Windows Defender
powershell.exe Set-MpPreference -MAPSReporting Advanced
powershell.exe Set-MpPreference -SubmitSamplesConsent 0
powershell.exe Set-MpPreference -PUAProtection enable
:: Activer au démarage "l'antimalware driver scan" pour analyser les drivers au démarage de la station de travail
reg add "HKEY_CURRENT_CONFIG\System\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /t REG_DWORD /d 3 /f


::#######################################################################
:: Actions bloqué
::#######################################################################
:: Interdire la creation de processus enfant pour Office
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
:: Interdire la creation de processus enfant pour Process Injection
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
:: Interdit l'appel d'API Win32 en macros
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
:: Interdire la creation de fichier executable pour Office
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
:: Interdire l'éxécution de scripts potentiellement dangereux
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
:: Interdire l'éxécution de contenue depuis une application email ou webmail
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
:: Interdire JavaScript et VBScript de lancer le telechargement de fichier executable
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
:: Bloquer l'accès au service de sous-syteme d'autorité de sécurité locale (LSASS)
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
:: Bloquer les processus non signé et sans confiance provenant d'une source en USB
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
:: Interdire la creation de processus enfant d'Adobe Reader
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
:: Block persistence through WMI event subscription
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
:: Bloquer le processus de creation originaire de PSExec et WMI commands
powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled


::#######################################################################
:: Activation de Windows Firewall
::#######################################################################
NetSh Advfirewall set allprofiles state on
:: Activation de la connection au Firewall
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
:: Bloque toute arrivé de connections au profile publique
netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
:: Activation de la protection de reseau Windows Defender Network Protection
powershell.exe Set-MpPreference -EnableNetworkProtection Enabled
:: Bloque les connections quand les programmes ne sont pas actifs
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


::#######################################################################
:: Paramètre de confidentialité Windows
::#######################################################################
:: Applique des limitations à Windows Analytics si activé
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 1 /f
:: Applique la telemetrie de Windows uniquement en mode securité
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v ShowedToastAtLevel /t REG_DWORD /d 1 /f
:: Desactiver ma localisation des données
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v Location /t REG_SZ /d Deny /f
:: Empecher le menue démarrer de fournir des informations d'internet et d'utilisiser la geolocalisation
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
:: Désactiver la publication de l'activité de l'utilisateur
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 1 /f
:: Désactiver la syncronisation au cloud
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
:: Désactiver les pubs à ID
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
:: Désactiver Windows GameDVR
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
:: Désactiver l'experience Microsoft consumer pour empêcher les notifications et sugestion d'applications à installer
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
:: Désactiver l'accès des sites web à la liste des langages
reg add "HKEY_USERS\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
:: Interdire les notifications sur l'écran de verouillage
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /d 1 /f


::#######################################################################
:: Active la connection avancé Windows 
::#######################################################################
:: Agrandissement de la taille des logs dans Windows Event
wevtutil sl Security /ms:1024000
wevtutil sl Application /ms:1024000
wevtutil sl System /ms:1024000
wevtutil sl "Windows Powershell" /ms:1024000
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000
:: Enregistre les données des lignes de commandes dans le registre (eventid 4688)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
:: Active les paramètres avancé
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
:: Active la connection au PowerShell
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
:: Active les détails des logs
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


::#######################################################################
:: Encryption
::#######################################################################
:: Encryption Ciphers: AES seulement
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /v Enabled /t REG_DWORD /d 0 /f
:: Encryption Hashes: SHA seulement
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" /v Enabled /t REG_DWORD /d 0xffffffff /f
:: Encryption Key Exchanges: tous autorisé
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" /v Enabled /t REG_DWORD /d 0xffffffff /f
:: Protocols d'encryption: TLS 1.0 ou supérieur 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v Enabled /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f
:: Encryption Cipher Suites (order)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v Functions /t REG_SZ /d "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA" /f
:: OCSP stapling
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v EnableOcspStaplingForSni /t REG_DWORD /d 1 /f
:: Activation de l'authentification forte pour .NET Framework 3.5
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
:: Activation de l'authentification forte pour .NET Framework 4.0/4.5.x
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f

::#######################################################################
:: Mise à jour forcé de Flash
::#######################################################################
%WINDIR%\system32\macromed\flash\FlashUtil_ActiveX.exe -update activex
%WINDIR%\system32\macromed\flash\FlashUtil_Plugin.exe -update plugin



::#######################################################################
::#######################################################################
:: Configuration de moteurs de recherche
::#######################################################################
::#######################################################################


::#######################################################################
:: Internet Explorer
::#######################################################################
:: Active les notifications quand un site essaie d'installer quelque chose
reg add "HKEY_USERS\.DEFAULT\Software\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f


::#######################################################################
:: Edge
::#######################################################################
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


::#######################################################################
:: Google Chrome
::#######################################################################
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
:: Désactive la syncronisation des données avec Google
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v SyncDisabled /d "1" /t REG_DWORD /f >NUL 2>&1
:: Désactive l'import de mot de passe sauvegardé
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v ImportSavedPasswords /d "0" /t REG_DWORD /f >NUL 2>&1
:: Désactive l'envoie de documents à Google Cloud Print
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v CloudPrintSubmitEnabled /d "0" /t REG_DWORD /f >NUL 2>&1
:: Désactive le proxy de Google Cloud Print
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v CloudPrintProxyEnabled /d "0" /t REG_DWORD /f >NUL 2>&1
:: Active l'isolation pour chaque sites
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v SitePerProcess /d "1" /t REG_DWORD /f >NUL 2>&1
:: Désactive l'envoie de raport après un crash
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v MetricsReportingEnabled /d "0" /t REG_DWORD /f >NUL 2>&1
:: Empèche Google Chrome de tourner en arrière plan
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v BackgroundModeEnabled /d "0" /t REG_DWORD /f >NUL 2>&1
:: Désactive les plugins trop vieux
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v AllowOutdatedPlugins /d "0" /t REG_DWORD /f >NUL 2>&1
:: Autorise les sites autorisé à faire des notifications
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /v DefaultNotificationsSetting /d "2" /t REG_DWORD /f >NUL 2>&1




::#######################################################################
::#######################################################################
:: Configuration des applications
::#######################################################################
::#######################################################################


::#######################################################################
:: Activation et configuration des paramètres de securité de Microsoft Office
::#######################################################################
:: Desactivation des macros et activation de la vue protégé (ProtectedView)
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


::#######################################################################
:: Configuration de Adobe Reader
::#######################################################################
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



::#######################################################################
::#######################################################################
:: Configuration suplémentaire
::#######################################################################
::#######################################################################

::#######################################################################
:: Commandes pour désinstaller les applications préinstallé
::#######################################################################
powershell.exe -command "Get-AppxPackage *Microsoft.BingWeather* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Getstarted* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Messaging* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.OneConnect* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Print3D* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.SkypeApp* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Wallet* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *microsoft.windowscommunicationsapps* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedbackHub* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsSoundRecorder* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.YourPhone* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.WindowsFeedback* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Windows.ContactSupport* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *PandoraMedia* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *AdobeSystemIncorporated. AdobePhotoshop* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Duolingo* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.BingNews* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *Microsoft.Advertising.Xaml* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *ActiproSoftware* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *EclipseManager* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *SpotifyAB.SpotifyMusic* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxPackage *king.com.* -AllUsers | Remove-AppxPackage"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.GetHelp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Getstarted'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.SkypeApp'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'microsoft.windowscommunicationsapps'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsFeedbackHub'} | Remove-AppxProvisionedPackage -Online"
powershell.exe -command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online"
wmic /interactive:off product where "name like 'Adobe Air%' and version like'%'" call uninstall
wmic /interactive:off product where "name like 'Adobe Flash%' and version like'%'" call uninstall
wmic /interactive:off product where "name like 'Java%' and version like'%'" call uninstall
wmic /interactive:off product where "name like 'Ask Part%' and version like'%'" call uninstall
wmic /interactive:off product where "name like 'searchAssistant%' and version like'%'" call uninstall
wmic /interactive:off product where "name like 'Weatherbug%' and version like'%'" call uninstall
wmic /interactive:off product where "name like 'ShopAtHome%' and version like'%'" call uninstall






:: Enforce NTLMv2 and LM authentication
:: reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
::
:: Prevent unencrypted passwords being sent to third-party SMB servers
:: reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
::
:: Prevent guest logons to SMB servers
:: reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
::
:: Force SMB server signing
:: reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
::
:: Enable Windows Defender Application Guard
:: powershell.exe Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard -norestart
::
:: Enable Windows Defender Credential Guard
:: reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f
:: reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 3 /f
:: reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v LsaCfgFlags /t REG_DWORD /d 1 /f
::
:: The following variant also enables forced ASLR and CFG but causes issues with several third party apps
:: powershell.exe Set-Processmitigation -System -Enable DEP,CFG,ForceRelocateImages,BottomUp,SEHOP
::
:: Block executable files from running unless they meet a prevalence, age, or trusted list criterion
:: powershell.exe Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
::
:: Enable Windows Defender real time monitoring
:: powershell.exe -command "Set-MpPreference -DisableRealtimeMonitoring $false"
::
:: Always re-process Group Policy even if no changes
:: Commented out as consumers don't typically use GPO
:: reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v NoGPOListChanges /t REG_DWORD /d 0 /f
::
:: Force logoff if smart card removed
:: Set to "2" for logoff, set to "1" for lock
:: Commented out as consumers don't typically use smart cards
:: reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SCRemoveOption /t REG_DWORD /d 2 /f
::
:: Restrict privileged local admin tokens being used from network 
:: Commented out as it only works on domain-joined assets
:: reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
::
:: Ensure outgoing secure channel traffic is encrytped
:: Commented out as it only works on domain-joined assets
:: reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f
::
:: Enforce LDAP client signing
:: Commented out as most consumers don't use LDAP auth
:: reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 1 /f
::
:: Prevent unauthenticated RPC connections
:: reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f
echo Programme termine
:END
pause
