@echo off
echo Please be sure to take the following information into account:
echo[

echo - A restore point will be created under the name [101m"WHOTRestorePoint"[0m.
echo - The program will modify the permissions/settings/authorizations... of certain files/folders/registries/services... on your computer (more information in the [101m"README.md"[0m file).
echo - If the tool crashes, [101mNever[0m restart it and use the restore point created at the beginning of the program.
echo - Close [101mALL[0m programs before running the tool.
echo[

@echo off

REM  :: Analyze of the permissions
    IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

REM :: If an error is detected admin permissions will be denied
if '%errorlevel%' NEQ '0' (
    echo Requesting administrator rights...
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
SET /P AREYOUSURE=Are you sure you want to run the program? (Y/N)? 
IF /I "%AREYOUSURE%" NEQ "Y" OR "y" GOTO END

echo Launch WHOT

powershell.exe -ExecutionPolicy Bypass -File "Script.ps1"