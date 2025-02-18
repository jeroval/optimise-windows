# Windows Scripts Toolkit

Ce dépôt regroupe une collection de scripts batch (.bat) visant à automatiser certaines tâches d'optimisation et de configuration sur les systèmes Windows. Ces outils peuvent être utilisés pour améliorer les performances, ajuster des paramètres réseau, ou encore simplifier l'installation de logiciels courants.

## Contenu du dépôt

### 1. optimisation_windows.bat
Ce script applique plusieurs réglages pour optimiser les performances générales de Windows :
- Désactivation de certains services inutiles pour libérer des ressources.
- Réduction des effets visuels pour améliorer la réactivité.
- Ajustement des paramètres d'alimentation pour favoriser les performances.
- Nettoyage des fichiers temporaires et optimisation du stockage.

### 2. TcpAckFrequency_TcpNoDelay.bat
Ce script modifie des paramètres spécifiques au protocole TCP pour améliorer la latence réseau :
- Activation de `TcpAckFrequency` : réduit le délai d'acquittement des paquets TCP, ce qui peut améliorer les performances dans les jeux en ligne ou les applications nécessitant une faible latence.
- Activation de `TcpNoDelay` : désactive le regroupement des paquets, envoyant les données immédiatement sans attendre de remplir les tampons, ce qui améliore encore la réactivité réseau.

### 3. installation_logiciels.bat
Ce script simplifie l'installation de plusieurs logiciels de base en automatisant les commandes :
- Télécharge et installe automatiquement des logiciels essentiels tels que :
  - Navigateurs web (Google Chrome, Mozilla Firefox)
  - Outils de compression (7-Zip, WinRAR)
  - Lecteurs multimédias (VLC Media Player)
  - Suites bureautiques gratuites (LibreOffice)
- Permet d'adapter facilement la liste des logiciels selon les besoins.

## Utilisation
1. Télécharger ou cloner ce dépôt.
2. Exécuter le script souhaité en tant qu'administrateur (clic droit > Exécuter en tant qu'administrateur).
3. Suivre les instructions affichées dans le terminal si applicable.

## Précautions
- Ces scripts effectuent des modifications sur le système. Veillez à comprendre chaque action avant de l'exécuter.
- Il est conseillé de créer un point de restauration avant toute manipulation.

## Contributions
Les contributions sont les bienvenues ! N'hésitez pas à proposer des améliorations ou de nouveaux scripts via des pull requests.

## Licence
Ce projet est sous licence MIT - voir le fichier LICENSE pour plus de détails.

