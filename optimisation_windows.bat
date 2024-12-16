@echo off
setlocal


REM Définir la politique d'exécution de PowerShell pour permettre l'exécution de scripts
powershell -Command "Set-ExecutionPolicy RemoteSigned -Scope Process -Force"

REM Suppression de fichiers dans différents répertoires
del /F /Q "%USERPROFILE%\Downloads\*.*" > nul 2>&1
del /S /F /Q "%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache\*.*" > nul 2>&1
del /S /F /Q "%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies\*.*" > nul 2>&1
del /S /F /Q "%Windir%\PerfLogs\*.*" > nul 2>&1
del /S /F /Q "%Windir%\SoftwareDistribution\Download\*.*" > nul 2>&1
del /S /F /Q "%Windir%\SoftwareDistribution\Logs\*.*" > nul 2>&1
del /S /F /Q "%Windir%\Temp\*.*" > nul 2>&1
del /S /F /Q "%temp%\*.*" > nul 2>&1
del /S /F /Q "%SystemRoot%\Prefetch\*.*" > nul 2>&1
del /F /Q "%windir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*.*" > nul 2>&1


REM Vider le cache DNS
ipconfig /flushdns
ipconfig /registerdns
ipconfig /release
ipconfig /renew


REM Nettoyage des journaux systeme
wevtutil cl Application
wevtutil cl System


REM Arrêt de certains services
net stop "DiagTrack"
net stop "WSearch"
net stop "dmwappushservice"
net stop "Spooler"
net stop "RemoteRegistry"
net stop "Fax"


REM Configuration des services
sc config "DiagTrack" start= disabled
sc config "SCardSvr" start= disabled
sc config "WSearch" start= disabled
sc config "WerSvc" start= disabled
sc config "dmwappushservice" start= disabled
sc config "Fax" start= disabled
sc config "Spooler" start= disabled
sc config "RemoteRegistry" start= disabled
sc config WMPNetworkSvc start= disabled


REM Configuration réseau
netsh winsock reset
netsh int tcp set global autotuninglevel=disabled
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=disabled
netsh int tcp set global congestionprovider=none

REM Définir la MTU à 1500 octets
netsh interface ipv4 set subinterface "Connexion au réseau local" mtu=1500 store=persistent


REM Désactiver IPV6
netsh interface ipv6 set privacy disabled
netsh interface teredo set state disabled


REM Configurer le pare-feu Windows
netsh advfirewall set allprofiles state on



REM Suppression du dossier Windows.old
rd /s /q "%Windir%\Windows.old"


REM Modification du registre pour diverses optimisations et désactivations
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Input\TIPC" /v DataCollectionPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v DefaultValue /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v DefaultValue /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows" /v DefaultValue /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v DefaultValue /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing" /v DefaultValue /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v DefaultValue /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v DefaultValue /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v DefaultValue /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ToolTipAnimation" /v DefaultValue /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ToolTipFade" /v DefaultValue /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\UIEffects" /v DefaultValue /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadFromPeers /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DownloadMode /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v NonBestEffortLimit /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Search\SetupCompletedSuccessfully" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xffffffff /f


REM Vérification des fichiers système
sfc /scannow


REM Mettre à jour les définitions de Windows Defender
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -SignatureUpdate


REM Effectuer une analyse complète avec Windows Defender
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 2



REM Suppression de certains fichiers dans le répertoire Explorer
start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\*.bak"
start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\*.ini"
start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\*.log"
start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\*.tmp"
start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache\*.*"
start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies\*.*"


REM Desactivation des fonctionnalites inutiles de Windows

dism /online /disable-feature /featurename:Internet-Explorer-Optional-amd64 /NoRestart
dism /online /disable-feature /featurename:WindowsMediaPlayer /NoRestart


REM Terminer certains processus
taskkill /F /IM ASCTray.exe
taskkill /F /IM CalculatorApp.exe
taskkill /F /IM Code.exe
taskkill /F /IM CodeSetup-stable*
taskkill /F /IM ElgatoAudioControlServer*
taskkill /F /IM FoxitPDFReaderUpdateService.exe
taskkill /F /IM GitHubDesktop.exe
taskkill /F /IM GoogleDriveFS.exe
taskkill /F /IM Greenshot.exe
taskkill /F /IM KeePass.exe
taskkill /F /IM ONENOTE*
taskkill /F /IM PhoneExperienceHost.exe
taskkill /F /IM StreamDeck.exe
taskkill /F /IM Taskmgr.exe
taskkill /F /IM ZSAService.exe
taskkill /F /IM ZSATray.exe
taskkill /F /IM ZSATunnel.exe
taskkill /F /IM chrome.exe
taskkill /F /IM discord*
taskkill /F /IM lghub_*
taskkill /F /IM msedge.exe
taskkill /F /IM notepad*
taskkill /F /IM steam*
taskkill /F /IM todolist*
taskkill /F /IM twitchstudiostreamdeck.exe
taskkill /F /IM wargamingerrormonitor.exe
taskkill /F /IM wgc.exe
taskkill /F /IM wslservice.exe
taskkill /F /IM Galaxy*
taskkill /F /IM GOG*
taskkill /F /IM Roblox*
taskkill /F /IM python.exe
taskkill /F /IM EABackgroundService.exe
taskkill /F /IM python.exe
taskkill /F /IM StreamDeck.exe
taskkill /F /IM wargamingerrormonitor.exe
taskkill /F /IM wgc.exe
taskkill /F /IM Xbox*
taskkill /F /IM gamingservices.exe



REM Ajouter la disposition de clavier QWERTY des États-Unis 
Install-Language -Language en-US
Set-WinUILanguageOverride -Language en-US
Get-WinUserLanguageList
$LangList = New-WinUserLanguageList en-US
Set-WinUserLanguageList $LangList



REM Recherche de mises à jour Windows Update
wuauclt /detectnow /updatenow
wuauclt.exe /updatenow

REM Mettre à jour les pilotes réseau
pnputil /scan-devices


REM Installer et import du module PSWindowsUpdate
powershell -Command "Install-Module -Name PSWindowsUpdate -Force -SkipPublisherCheck"
powershell -Command "Import-Module PSWindowsUpdate"


REM Recherche et installation des mises à jour Windows
powershell -Command "Get-WindowsUpdate -AcceptAll -IgnoreReboot"
powershell -Command "Install-WindowsUpdate -AcceptAll -IgnoreReboot"


REM Créer un fichier PowerShell temporaire pour mise à jour windows
set TempScript=%TEMP%\temp_update_script.ps1

echo function Force-WindowsUpdates { > %TempScript%
echo     $session = New-Object -ComObject 'Microsoft.Update.Session' >> %TempScript%
echo     $updater = $session.CreateUpdateSearcher() >> %TempScript%
echo     $searchResult = $updater.Search('IsInstalled=0') >> %TempScript%
echo     if ($searchResult.Updates.Count -gt 0) { >> %TempScript%
echo         $downloader = $session.CreateUpdateDownloader() >> %TempScript%
echo         $downloader.Updates = $searchResult.Updates >> %TempScript%
echo         $downloader.Download() >> %TempScript%
echo         $installer = $session.CreateUpdateInstaller() >> %TempScript%
echo         $installer.Updates = $searchResult.Updates >> %TempScript%
echo         $installResult = $installer.Install() >> %TempScript%
echo         if ($installResult.RebootRequired) { >> %TempScript%
echo             Write-Host 'Des mises à jour ont été installées et nécessitent un redémarrage.' >> %TempScript%
echo         } else { >> %TempScript%
echo             Write-Host 'Mises à jour installées avec succès.' >> %TempScript%
echo         } >> %TempScript%
echo     } else { >> %TempScript%
echo         Write-Host 'Aucune mise à jour disponible.' >> %TempScript%
echo     } >> %TempScript%
echo     Write-Host 'Pause de 5 secondes pour lecture...' >> %TempScript%
echo     Start-Sleep -Seconds 5 >> %TempScript%
echo } >> %TempScript%
echo Force-WindowsUpdates >> %TempScript%


REM Exécuter le script PowerShell temporaire
powershell -ExecutionPolicy Bypass -File %TempScript%


REM Supprimer le script PowerShell temporaire
del %TempScript%





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







REM Demander à l'utilisateur s'il souhaite exécuter la défragmentation
echo Voulez-vous exécuter la défragmentation des disques ? (o/n):
set /p choice=
if /i "%choice%"=="o" (
    defrag /C
)

echo Nettoyage et optimisation terminés !
pause
endlocal
