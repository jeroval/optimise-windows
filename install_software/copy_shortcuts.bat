@echo off
setlocal enabledelayedexpansion

:: Définition des chemins des raccourcis
set "userStartMenu=%APPDATA%\Microsoft\Windows\Start Menu\Programs"
set "globalStartMenu=C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
set "targetFolder=%USERPROFILE%\Desktop\Raccourcis_Menu_Demarrer"

:: Création du dossier cible sur le Bureau
if not exist "%targetFolder%" mkdir "%targetFolder%"

:: Fichier temporaire contenant les dossiers à exclure
set "excludeFile=%temp%\exclude_paths.txt"
(
    echo %APPDATA%\Microsoft\Windows\Start Menu\Programs\Accessibility
    echo %APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools
    echo %APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell
    echo C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories
    echo C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools
    echo C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Outils Microsoft Office
    echo C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Windows PowerShell
) > "%excludeFile%"

:: Liste des mots interdits dans les noms de fichiers
set "excludeWords=Help Désinstaller License Manuel documentation Documentation Release Readme Uninstall Java"

echo.
echo ===========================
echo   Recherche des raccourcis
echo ===========================
echo.

:: Boucle sur tous les raccourcis utilisateur et globaux
for /r "%userStartMenu%" %%f in (*.lnk) do call :check_and_copy "%%f"
for /r "%globalStartMenu%" %%f in (*.lnk) do call :check_and_copy "%%f"

goto :end

:: Vérification et copie des raccourcis
:check_and_copy
set "filePath=%~1"
set "fileName=%~nx1"

:: Vérifier si le fichier appartient à un dossier exclu
for /f "delims=" %%e in (%excludeFile%) do (
    echo "!filePath!" | findstr /C:"%%e" >nul
    if not errorlevel 1 (
        echo [EXCLU DOSSIER] !filePath!
        exit /b
    )
)

:: Vérifier si le fichier contient un mot interdit
for %%w in (%excludeWords%) do (
    echo "!fileName!" | findstr /C:"%%w" >nul
    if not errorlevel 1 (
        echo [EXCLU MOT INTERDIT] !filePath!
        exit /b
    )
)

:: Si non exclu, copier le raccourci
echo [COPIE] !filePath!
copy "!filePath!" "%targetFolder%" >nul
exit /b

:end
echo.
echo ================================
echo   Tous les raccourcis copiés
echo   Destination: %targetFolder%
echo ================================
echo.
pause
