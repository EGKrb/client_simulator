# Rapport d'impact de l'agent de securite sur le pipeline de test

- Date : 2026-09-22 20:58:11
- Machine : DESKTOP-83V74Q6
- OS : Microsoft Windows 11 Professionnel 10.0.26200
- Iterations mesurees : 15
- Processus cible : TargetPlayerBeta.exe (PID 9648)

## Agent de securite detecte

- WMI SecurityCenter2 : Windows Defender [etat: actif]
- Processus securite actifs : MsMpEng, OneDrive.Sync.Service

## Mesures (microsecondes, net hors overhead du harness, mediane robuste)

| Operation | Min (us) | Mediane (us) | Moyenne (us) | Coefficient de latence | Impact |
|---|---|---|---|---|---|
| Memoire : scan AOB (16MB) | 50771 | 51636.9 | 51564.87 | 1 | Faible |
| I/O fichier : lecture  cache (8MB) | 2535.47 | 3586.67 | 3834.5 | 60.01 | CRITIQUE |
| I/O fichier : ecriture cache (8MB) | 2824.67 | 3132.27 | 3165.57 | 52.41 | CRITIQUE |
| Syscall : NtQuerySystem | 1230.07 | 1392.07 | 1441.29 | 55.53 | CRITIQUE |
| I/O fichier : ecriture config (petit) | 243.97 | 297.47 | 323.98 | 4.98 | CRITIQUE |
| Syscall : NtProtectMem | 95.47 | 104.97 | 110.12 | 4.19 | CRITIQUE |
| I/O fichier : lecture  config (petit) | 41.17 | 59.77 | 934.21 | 1 | Faible |
| Processus : NtQueryInformationProcess | 31.07 | 34.67 | 37.78 | 1.12 | Faible |
| Processus : OpenProcess + CloseHandle | 25.37 | 30.97 | 35.57 | 1 | Faible |
| Syscall : NtWriteMem | 24.17 | 25.07 | 28.56 | 1 | Faible |

## Operations les plus couteuses

- **I/O fichier : lecture  cache (8MB)** : 3586.67 us (mediane), x60.01 la reference de categorie
- **I/O fichier : ecriture cache (8MB)** : 3132.27 us (mediane), x52.41 la reference de categorie
- **Syscall : NtQuerySystem** : 1392.07 us (mediane), x55.53 la reference de categorie
- **I/O fichier : ecriture config (petit)** : 297.47 us (mediane), x4.98 la reference de categorie
- **Syscall : NtProtectMem** : 104.97 us (mediane), x4.19 la reference de categorie

## Methode

- Stopwatch haute resolution (1 tick = 100 ns).
- Lecture observationnelle uniquement : aucune donnee systeme ou processus n'est modifiee.
- Coefficient de latence = mediane de l'operation / mediane la plus legere de la meme categorie (FileIO, Memory, Process, Syscall).

> Note : en presence d'une exclusion antivirus du repertoire TEMP, les valeurs I/O peuvent etre optimistes. Rejouer dans le repertoire de travail reel si besoin.
