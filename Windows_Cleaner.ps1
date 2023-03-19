#Elevation des priviledges
Write-Output "Elevation des priviledges..."
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)


#Nom de la fenetre
$Host.UI.RawUI.WindowTitle = "Windows_Cleaner $([char]0x00A9)" 
vssadmin delete shadows /all /quiet | Out-Null


#Creation d'un point de restauration
Write-Host "Creation d'un point de restauration..."
New-ItemProperty -Path "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Type "DWORD" -Value 0 -Force
Checkpoint-Computer -Description "Windows_Cleaner" -RestorePointType MODIFY_SETTINGS
Write-Host "Point de restauration créé avec succès !" -ForegroundColor Green


Write-Host "Le nettoyage du disque commence..."


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