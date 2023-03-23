@echo off
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
powershell.exe -ExecutionPolicy Bypass -File "Script.ps1"