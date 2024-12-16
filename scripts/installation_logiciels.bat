@echo off
setlocal

echo Creation du script PowerShell temporaire pour installer winget
set TempScript=%TEMP%\temp_winget_install_script.ps1

echo Set-ExecutionPolicy RemoteSigned -Scope Process -Force > %TempScript%
echo $progressPreference = 'silentlyContinue' >> %TempScript%
echo Write-Host "Installing WinGet PowerShell module from PSGallery..." >> %TempScript%
echo Install-PackageProvider -Name NuGet -Force ^| Out-Null >> %TempScript%
echo Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery ^| Out-Null >> %TempScript%
echo Write-Host "Using Repair-WinGetPackageManager cmdlet to bootstrap WinGet..." >> %TempScript%
echo Repair-WinGetPackageManager >> %TempScript%
echo Write-Host "Done." >> %TempScript%

echo Executer le script PowerShell temporaire

powershell -ExecutionPolicy Bypass -File %TempScript%

echo Supprimer le script PowerShell temporaire
del %TempScript%

echo Mise à jour des sources winget...
winget source update
winget upgrade --id Microsoft.Winget.Client
echo.


echo Mise à jour des applications installees...
winget upgrade --all --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
echo


REM Liste des identifiants des applications à installer
set apps=^
Microsoft.AppInstaller ^
Notepad++.Notepad++ ^
Google.Chrome ^
7zip.7zip ^
VideoLAN.VLC ^
Microsoft.VisualStudioCode ^
PuTTY.PuTTY ^
WinSCP.WinSCP ^
Greenshot.Greenshot ^
GitHub.GitHubDesktop ^
Oracle.JavaRuntimeEnvironment ^
Python.Python.3.6 ^
Git.Git ^
Discord.Discord ^
JGraph.Draw ^
OBSProject.OBSStudio ^
KeePass.KeePass ^
Valve.Steam ^
EpicGames.EpicGamesLauncher ^
ElectronicArts.EADesktop ^
Roblox.Roblox ^
Wargaming.GameCenter ^
Amazon.Games ^
GOG.Galaxy ^
Ubisoft.Connect ^
Foxit.FoxitReader ^
Google.GoogleDrive ^
Nvidia.GeForceExperience ^
Nvidia.Broadcast ^
9NF8H0H7WMLT ^
mRemoteNG.mRemoteNG ^
eTeks.SweetHome3D ^
Microsoft.Office ^
WeMod.WeMod ^
ItchIo.Itch ^
LucentWebCreative.GameJolt ^
Oracle.VirtualBox ^
XPDNZJFNCR1B07 ^
9MV0B5HZVK9Z ^
Wondershare.Filmora ^
XP8BT8DW290MPQ ^
Google.CloudSDK ^
IDRIX.VeraCrypt ^
Famatech.AdvancedIPScanner ^
Logitech.GHUB ^
Piriform.CCleaner

REM Boucle d'installation pour chaque application
for %%a in (%apps%) do (
    echo --------------------------
    echo Installation de : %%a
    echo.
    winget install --id=%%a --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
    echo.
)


echo Installation et mise a jour du module Azure cloud Az
powershell -Command "Install-Module -Name Az -Repository PSGallery -Force"
echo
powershell -Command "Update-Module -Name Az"
echo 


echo Installation .NET Framework 3.5
DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess
powershell -Command "Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like '*NetFx*' }"
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5" /s
DISM /Online /Get-Features | findstr "NetFx"



echo --------------------------
echo Installation terminée !
echo Pour ajouter ou rechercher un paquet manquant ou obsolete, utilisez winget search
echo
pause
endlocal
