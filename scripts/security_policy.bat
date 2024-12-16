@echo off

:: Activer le verrouillage du compte Administrateur
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v AllowAdministratorLockout /t REG_DWORD /d 1 /f

:: Définir le seuil de verrouillage à 5 tentatives
net accounts /lockoutthreshold:5

:: Définir la durée de verrouillage à 15 minutes
net accounts /lockoutduration:15

:: Réinitialiser le compteur de verrouillages du compte après 15 minutes
net accounts /lockoutwindow:15

:: Désactiver le stockage des LM Hash
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NoLMHash /t REG_DWORD /d 1 /f

:: Configurer la politique de verrouillage automatique
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 600 /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 1 /f


:: Activer le pare-feu Windows pour tous les profils
netsh advfirewall set allprofiles state on

:: Désactiver le compte Invité
net user Guest /active:no


echo Les paramètres de sécurité ont été mis à jour avec succès.
pause
