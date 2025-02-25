@echo off
setlocal enabledelayedexpansion

REM Lister toutes les interfaces reseau Wi-Fi
echo Recherche des interfaces reseau Wi-Fi...

REM Boucle sur chaque interface Wi-Fi
for /f "tokens=2 delims=:" %%G in ('netsh wlan show interfaces ^| findstr /r /c:"^ *GUID"') do (
    set "interfaceGUID=%%G"
    set "interfaceGUID=!interfaceGUID:~1!"
    echo GUID trouve pour une interface Wi-Fi : !interfaceGUID!

    REM Appliquer les paramètres TcpAckFrequency et TcpNoDelay
    echo Application des paramètres TcpAckFrequency et TcpNoDelay pour interface : !interfaceGUID!...
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{!interfaceGUID!}" /v TcpAckFrequency /t REG_DWORD /d 1 /f >nul
    if %errorlevel% neq 0 (
        echo Échec de la configuration de TcpAckFrequency pour interface : !interfaceGUID!.
    ) else (
        echo TcpAckFrequency configure avec succes pour interface : !interfaceGUID!.
    )
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{!interfaceGUID!}" /v TcpNoDelay /t REG_DWORD /d 1 /f >nul
    if %errorlevel% neq 0 (
        echo Échec de la configuration de TcpNoDelay pour interface : !interfaceGUID!.
    ) else (
        echo TcpNoDelay configure avec succes pour interface : !interfaceGUID!.
    )
)

echo Configuration des interfaces reseau Wi-Fi terminee.
pause
endlocal