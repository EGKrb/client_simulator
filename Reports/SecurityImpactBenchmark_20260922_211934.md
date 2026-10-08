# Rapport d'impact de l'agent de securite sur le pipeline de test

- Date : 2026-09-22 21:19:34
- Machine : DESKTOP-83V74Q6
- OS : Microsoft Windows 11 Professionnel 10.0.26200
- Iterations mesurees : 15
- Processus cible : C:\Users\ASUS\AppData\Local\Target\Versions\version-2366ba214ec740ca\TargetPlayerBeta.exe (PID 13444)

## Agent de securite detecte

- WMI SecurityCenter2 : Windows Defender [etat: actif]
- Processus securite actifs : MsMpEng, OneDrive.Sync.Service

## Mesures (microsecondes, net hors overhead du harness, mediane robuste)

| Operation | Min (us) | Mediane (us) | Moyenne (us) | Coefficient de latence | Impact |
|---|---|---|---|---|---|
| Memoire : scan AOB (16MB) | 51960.81 | 54089.61 | 53741.49 | 1 | Faible |
| I/O fichier : lecture  cache (8MB) | 2250.06 | 2928.26 | 4465.35 | 25.56 | CRITIQUE |
| I/O fichier : ecriture cache (8MB) | 2675.46 | 2827.36 | 2879.15 | 24.68 | CRITIQUE |
| Syscall : NtQuerySystem | 1453.31 | 1631.91 | 1645.22 | 75.17 | CRITIQUE |
| I/O fichier : ecriture config (petit) | 276.66 | 308.56 | 334.39 | 2.69 | Important |
| I/O fichier : lecture  config (petit) | 87.16 | 114.56 | 132.55 | 1 | Faible |
| Syscall : NtProtectMem | 88.91 | 92.01 | 93.22 | 4.24 | CRITIQUE |
| Processus : ReadProcessMemory (64o) | 40.92 | 45.32 | 49.03 | 1 | Faible |
| Syscall : NtWriteMem | 20.41 | 21.71 | 22.9 | 1 | Faible |
| Processus : NtQueryInformationProcess | 7.12 | 16.22 | 21.97 | 1 | Faible |
| Processus : OpenProcess + CloseHandle | 0 | 0 | 0.17 | 1 | Faible |

## Operations les plus couteuses

- **I/O fichier : lecture  cache (8MB)** : 2928.26 us (mediane), x25.56 la reference de categorie
- **I/O fichier : ecriture cache (8MB)** : 2827.36 us (mediane), x24.68 la reference de categorie
- **Syscall : NtQuerySystem** : 1631.91 us (mediane), x75.17 la reference de categorie
- **I/O fichier : ecriture config (petit)** : 308.56 us (mediane), x2.69 la reference de categorie
- **Syscall : NtProtectMem** : 92.01 us (mediane), x4.24 la reference de categorie

## Methode

- Stopwatch haute resolution (1 tick = 100 ns).
- Lecture observationnelle uniquement : aucune donnee systeme ou processus n'est modifiee.
- Coefficient de latence = mediane de l'operation / mediane la plus legere de la meme categorie (FileIO, Memory, Process, Syscall).

> Note : en presence d'une exclusion antivirus du repertoire TEMP, les valeurs I/O peuvent etre optimistes. Rejouer dans le repertoire de travail reel si besoin.
