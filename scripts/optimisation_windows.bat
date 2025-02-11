@echo off
setlocal


echo _____________________________________________________________________________________________________________
echo Definir la politique d'execution de PowerShell pour permettre l'execution de scripts
echo _____________________________________________________________________________________________________________

powershell -Command "Set-ExecutionPolicy RemoteSigned -Scope Process -Force"


echo _____________________________________________________________________________________________________________
echo Suppression de fichiers dans différents répertoires
echo _____________________________________________________________________________________________________________


del /F /Q "%USERPROFILE%\Downloads\*.*" > nul 2>&1
del /F /Q "%windir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*.*" > nul 2>&1
del /F /S /Q "%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\*.db" > nul 2>&1
del /F /S /Q "C:\ProgramData\Microsoft\Diagnosis\*.rbs" > nul 2>&1
del /F /S /Q "C:\ProgramData\Microsoft\Diagnosis\*.rbs.bak" > nul 2>&1
del /F /S /Q "C:\ProgramData\Microsoft\Windows Defender\Definition Updates\Backup\*.*" > nul 2>&1
del /F /S /Q "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Store\*.*" > nul 2>&1
del /F /S /Q "C:\ProgramData\Microsoft\Windows\WER\*.*" > nul 2>&1
del /F /S /Q "C:\Users\%USERNAME%\AppData\Local\Temp\*.*" > nul 2>&1
del /F /S /Q "C:\Windows\Logs\*.*" > nul 2>&1
del /F /S /Q "C:\Windows\MEMORY.DMP" > nul 2>&1
del /F /S /Q "C:\Windows\Minidump\*.*" > nul 2>&1
del /F /S /Q "C:\Windows\Prefetch\*.*" > nul 2>&1
del /F /S /Q "C:\Windows\SoftwareDistribution\DataStore\Logs\*.*" > nul 2>&1
del /F /S /Q "C:\Windows\SysWOW64\LogFiles\*.*" > nul 2>&1
del /F /S /Q "C:\Windows\System32\SleepStudy\*.*" > nul 2>&1
del /F /S /Q "%SystemRoot%\Prefetch\*.*" > nul 2>&1
del /S /F /Q "%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache\*.*" > nul 2>&1
del /S /F /Q "%USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies\*.*" > nul 2>&1
del /S /F /Q "%Windir%\PerfLogs\*.*" > nul 2>&1
del /S /F /Q "%Windir%\SoftwareDistribution\Download\*.*" > nul 2>&1
del /S /F /Q "%Windir%\SoftwareDistribution\Logs\*.*" > nul 2>&1
del /S /F /Q "%Windir%\Temp\*.*" > nul 2>&1
del /S /F /Q "%temp%\*.*" > nul 2>&1


rd /s /q "C:\Windows\Logs\CBS"
rd /s /q "C:\Windows\Panther"
rd /s /q "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp"
rd /s /q "C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp"
rd /s /q "C:\Windows\System32\LogFiles"
rd /s /q "C:\Windows\System32\wbem\Logs"
rd /s /q "C:\Windows\Temp"
rd /s /q "C:\Windows\WinSxS\Temp\PendingDeletes"
rd /s /q "C:\Windows\WinSxS\Temp\PendingRenames"


echo _____________________________________________________________________________________________________________
echo Vider le cache DNS
echo _____________________________________________________________________________________________________________

ipconfig /flushdns
ipconfig /registerdns
ipconfig /release
ipconfig /renew


echo _____________________________________________________________________________________________________________
echo Nettoyage des journaux systeme
echo _____________________________________________________________________________________________________________

wevtutil cl Application
wevtutil cl System


echo _____________________________________________________________________________________________________________
echo Nettoyage du cache Windows Defender
echo _____________________________________________________________________________________________________________

"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -removedefinitions -dynamicsignatures
del /F /S /Q "C:\ProgramData\Microsoft\Windows Defender\Scans\*.*"



echo _____________________________________________________________________________________________________________
echo Compression des fichiers système
echo _____________________________________________________________________________________________________________

Compact.exe /CompactOS:always


echo _____________________________________________________________________________________________________________
echo Suppression des anciennes mises à jour Windows
echo _____________________________________________________________________________________________________________

dism /online /Cleanup-Image /StartComponentCleanup /ResetBase
dism /online /Cleanup-Image /AnalyzeComponentStore
dism /online /Cleanup-Image /SPSuperseded


echo _____________________________________________________________________________________________________________
echo Réduire le cache de Windows Update
echo _____________________________________________________________________________________________________________

net stop wuauserv
rd /s /q C:\Windows\SoftwareDistribution
net start wuauserv


echo _____________________________________________________________________________________________________________
echo Supprimer les fichiers d’installation des mises à jour Windows
echo _____________________________________________________________________________________________________________

cleanmgr /verylowdisk


echo _____________________________________________________________________________________________________________
echo Suppression du dossier Windows.old
echo _____________________________________________________________________________________________________________

rd /s /q "%Windir%\Windows.old"


echo _____________________________________________________________________________________________________________
echo Désactiver et vider le fichier d’hibernation gain de 2 à 5 Go
echo _____________________________________________________________________________________________________________

powercfg -h off


echo _____________________________________________________________________________________________________________
echo Désactiver complètement le fichier d’échange SWAP
echo _____________________________________________________________________________________________________________

wmic pagefileset where name="C:\\pagefile.sys" delete


echo _____________________________________________________________________________________________________________
echo Supprimer et désactiver les points de restaurations
echo _____________________________________________________________________________________________________________

vssadmin delete shadows /all /quiet
Disable-ComputerRestore -Drive "C:\"




echo _____________________________________________________________________________________________________________
echo Arret des services facultatifs
echo _____________________________________________________________________________________________________________


net stop "DiagTrack"
net stop "Fax"
net stop "RemoteRegistry"
net stop "RetailDemo"
net stop "SysMain"
net stop "WMPNetworkSvc"
net stop "WSearch"
net stop "dmwappushservice"


echo _____________________________________________________________________________________________________________
echo Desactivation des services facultatifs
echo _____________________________________________________________________________________________________________

sc config "DiagTrack" start= disabled
sc config "Fax" start= disabled
sc config "RemoteRegistry" start= disabled
sc config "RetailDemo" start= disabled
sc config "SCardSvr" start= disabled
sc config "Spooler" start= disabled
sc config "SysMain" start= disabled
sc config "TabletInputService" start= disabled
sc config "WMPNetworkSvc" start= disabled
sc config "WSearch" start= disabled
sc config "WerSvc" start= disabled
sc config "dmwappushservice" start= disabled


echo _____________________________________________________________________________________________________________
echo Configuration réseau
echo _____________________________________________________________________________________________________________

netsh winsock reset
netsh int tcp reset
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=disabled
netsh int tcp set supplemental template=internet congestionprovider=none


echo _____________________________________________________________________________________________________________
echo Définir la MTU à 1500 octets
echo _____________________________________________________________________________________________________________

for /f "tokens=1-4*" %%A in ('netsh interface show interface ^| findstr /I "Wi-Fi"') do (
    echo Modification de l'interface Wi-Fi : %%E
    netsh interface ipv4 set subinterface "%%E" mtu=1500 store=persistent
    if %errorlevel%==0 (
        echo MTU configuré avec succès pour "%%E".
    ) else (
        echo Erreur lors de la configuration pour "%%E".
    )
)


echo _____________________________________________________________________________________________________________
echo Désactiver IPV6
echo _____________________________________________________________________________________________________________

netsh interface ipv6 set privacy disabled
netsh interface teredo set state disabled


echo _____________________________________________________________________________________________________________
echo Configurer le pare-feu Windows
echo _____________________________________________________________________________________________________________

netsh advfirewall set allprofiles state on



echo _____________________________________________________________________________________________________________
echo Modification du registre pour diverses optimisations et désactivations
echo _____________________________________________________________________________________________________________


reg add "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 600 /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 08 /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 32 /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9012038010000000 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Input\TIPC" /v DataCollectionPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AllowAutoGameMode /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableAeroPeek /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 1 /f
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
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /v AlwaysHibernateThumbnails /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /v UseAnimations /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 0xffffffff /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadFromPeers /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DownloadMode /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v NonBestEffortLimit /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Search\SetupCompletedSuccessfully" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v AllowAdministratorLockout /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v AdditionalCriticalWorkerThreads /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v SecondLevelDataCache /t REG_DWORD /d 512 /f



echo _____________________________________________________________________________________________________________
echo Suppression des packages inutiles
echo _____________________________________________________________________________________________________________

REM powershell -Command "Get-AppxPackage *MicrosoftTeams* | Remove-AppxPackage"
REM powershell -Command "Get-AppxPackage *Office* | Remove-AppxPackage"
REM powershell -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage"
REM powershell -Command "Get-AppxPackage *Windows.Photos* | Remove-AppxPackage"
REM powershell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
REM powershell -Command "Get-AppxPackage *WindowsCalculator* | Remove-AppxPackage"
REM powershell -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
REM powershell -Command "Get-AppxPackage *WindowsMail* | Remove-AppxPackage"
REM powershell -Command "Get-AppxPackage *WindowsTerminal* | Remove-AppxPackage"
REM powershell -Command "Get-AppxPackage *XboxGameOverlay* | Remove-AppxPackage"
REM powershell -Command "Get-AppxPackage *XboxGamingOverlay* | Remove-AppxPackage"
REM powershell -Command "Get-AppxPackage *XboxSpeechToTextOverlay* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *3DBuilder* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Clipchamp* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Disney* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Facebook* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *GetHelp* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *HEIFImageExtension* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *LinkedIn* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *MSNWeather* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Messaging* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *MicrosoftAdvertising* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *MixedReality* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Netflix* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *News* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Paint3D* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Spotify* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *StickyNotes* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Skype* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *TikTok* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Twitter* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *VP9VideoExtensions* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Wallet* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Weather* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *WebExperience* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *WebpImageExtension* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *Widgets* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *WindowsFeedbackHub* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *WindowsStore* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *YourPhone* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *ZuneMusic* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *ZuneVideo* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *FeedbackHub* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *BingNews* | Remove-AppxPackage"
powershell -Command "Get-AppxPackage *WindowsPeople* | Remove-AppxPackage"

echo _____________________________________________________________________________________________________________
echo Vérification des fichiers système
echo _____________________________________________________________________________________________________________

sfc /scannow


echo _____________________________________________________________________________________________________________
echo Mettre à jour les définitions de Windows Defender
echo _____________________________________________________________________________________________________________

"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -SignatureUpdate


echo _____________________________________________________________________________________________________________
echo Effectuer une analyse complète avec Windows Defender
echo _____________________________________________________________________________________________________________

"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 2


echo _____________________________________________________________________________________________________________
echo definir les politiques de securite sur les comptes
echo _____________________________________________________________________________________________________________

net accounts /lockoutduration:15
net accounts /lockoutthreshold:5
net accounts /lockoutwindow:15
net user Guest /active:no


echo _____________________________________________________________________________________________________________
echo Suppression de certains fichiers dans le répertoire Explorer
echo _____________________________________________________________________________________________________________

start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\*.bak"
start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\*.ini"
start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\*.log"
start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer\*.tmp"
start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\INetCache\*.*"
start "" /b "cmd /c echo y | del /F /Q %USERPROFILE%\AppData\Local\Microsoft\Windows\INetCookies\*.*"


echo _____________________________________________________________________________________________________________
echo Desactivation des fonctionnalites inutiles de Windows
echo _____________________________________________________________________________________________________________

dism /online /disable-feature /featurename:Internet-Explorer-Optional-amd64 /NoRestart
dism /online /disable-feature /featurename:WindowsMediaPlayer /NoRestart


echo _____________________________________________________________________________________________________________
echo Terminer certains processus
echo _____________________________________________________________________________________________________________

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


echo _____________________________________________________________________________________________________________
echo Ajouter la disposition de clavier QWERTY des États-Unis 
echo _____________________________________________________________________________________________________________

powershell -Command "Install-Language -Language en-US"
powershell -Command "Set-WinUILanguageOverride -Language en-US"
powershell -Command "Get-WinUserLanguageList"
powershell -Command "$LangList = New-WinUserLanguageList en-US"
powershell -Command "Set-WinUserLanguageList $LangList"


echo _____________________________________________________________________________________________________________
echo Recherche de mises à jour Windows Update
echo _____________________________________________________________________________________________________________

wuauclt /detectnow /updatenow
wuauclt.exe /updatenow


echo _____________________________________________________________________________________________________________
echo Mettre à jour les pilotes réseau
echo _____________________________________________________________________________________________________________

pnputil /scan-devices

echo _____________________________________________________________________________________________________________
echo Installer et import du module PSWindowsUpdate
echo _____________________________________________________________________________________________________________

powershell -Command "Install-Module -Name PSWindowsUpdate -Force -SkipPublisherCheck"
powershell -Command "Import-Module PSWindowsUpdate"


echo _____________________________________________________________________________________________________________
echo Recherche et installation des mises à jour Windows
echo _____________________________________________________________________________________________________________

powershell -Command "Get-WindowsUpdate -AcceptAll -IgnoreReboot"
powershell -Command "Install-WindowsUpdate -AcceptAll -IgnoreReboot"

echo _____________________________________________________________________________________________________________
echo Créer un fichier PowerShell temporaire pour mise à jour windows
echo _____________________________________________________________________________________________________________

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


echo _____________________________________________________________________________________________________________
echo Exécuter le script PowerShell temporaire
echo _____________________________________________________________________________________________________________

powershell -ExecutionPolicy Bypass -File %TempScript%


echo _____________________________________________________________________________________________________________
echo Supprimer le script PowerShell temporaire
echo _____________________________________________________________________________________________________________

del %TempScript%


echo _____________________________________________________________________________________________________________
echo Nettoyage et optimisation terminés !
echo _____________________________________________________________________________________________________________


pause
endlocal