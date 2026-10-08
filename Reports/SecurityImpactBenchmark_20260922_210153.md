# Rapport d'impact de l'agent de securite sur le pipeline de test

- Date : 2026-09-22 21:01:53
- Machine : DESKTOP-83V74Q6
- OS : Microsoft Windows 11 Professionnel 10.0.26200
- Iterations mesurees : 15
- Processus cible : C:\Users\ASUS\AppData\Local\Target\Versions\version-2366ba214ec740ca\TargetPlayerBeta.exe (PID 9648)

## Agent de securite detecte

- WMI SecurityCenter2 : Windows Defender [etat: actif]
- Processus securite actifs : MsMpEng, OneDrive.Sync.Service

## Mesures (microsecondes, net hors overhead du harness, mediane robuste)

| Operation | Min (us) | Mediane (us) | Moyenne (us) | Coefficient de latence | Impact |
|---|---|---|---|---|---|
| Memoire : scan AOB (16MB) | 53332.85 | 54685.55 | 54486.64 | 1 | Faible |
| I/O fichier : ecriture cache (8MB) | 3438.73 | 3711.63 | 3743.57 | 35.34 | CRITIQUE |
| I/O fichier : lecture  cache (8MB) | 2727.93 | 3209.13 | 3670.16 | 30.55 | CRITIQUE |
| Syscall : NtQuerySystem | 1629.79 | 2348.59 | 2319.6 | 110.31 | CRITIQUE |
| I/O fichier : ecriture config (petit) | 321.33 | 354.43 | 349.08 | 3.37 | Important |
| I/O fichier : lecture  config (petit) | 96.23 | 105.03 | 130.86 | 1 | Faible |
| Syscall : NtProtectMem | 90.99 | 103.79 | 104 | 4.88 | CRITIQUE |
| Processus : NtQueryInformationProcess | 33.56 | 53.56 | 57.75 | 2.12 | Important |
| Processus : OpenProcess + CloseHandle | 17.66 | 25.26 | 32.75 | 1 | Faible |
| Syscall : NtWriteMem | 18.69 | 21.29 | 23.26 | 1 | Faible |

## Operations les plus couteuses

- **I/O fichier : ecriture cache (8MB)** : 3711.63 us (mediane), x35.34 la reference de categorie
- **I/O fichier : lecture  cache (8MB)** : 3209.13 us (mediane), x30.55 la reference de categorie
- **Syscall : NtQuerySystem** : 2348.59 us (mediane), x110.31 la reference de categorie
- **I/O fichier : ecriture config (petit)** : 354.43 us (mediane), x3.37 la reference de categorie
- **Syscall : NtProtectMem** : 103.79 us (mediane), x4.88 la reference de categorie
- **Processus : NtQueryInformationProcess** : 53.56 us (mediane), x2.12 la reference de categorie

## Methode

- Stopwatch haute resolution (1 tick = 100 ns).
- Lecture observationnelle uniquement : aucune donnee systeme ou processus n'est modifiee.
- Coefficient de latence = mediane de l'operation / mediane la plus legere de la meme categorie (FileIO, Memory, Process, Syscall).

> Note : en presence d'une exclusion antivirus du repertoire TEMP, les valeurs I/O peuvent etre optimistes. Rejouer dans le repertoire de travail reel si besoin.
