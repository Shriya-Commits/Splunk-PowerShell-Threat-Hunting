# Investigation Findings

## Scenario
Boss of the SOC v3 dataset — Frothly brewery breach. Goal: determine if PowerShell
was used as an attack vector and identify the affected accounts.

## Step 1 — Baseline: Who is running PowerShell?
Query 01 returned 5 accounts running powershell.exe across the environment:
FyodorMalteskesko (dominant), AlBungstein, BruceGist, BudStoll, and FYODOR-L$.
FyodorMalteskesko accounted for the large majority of executions — immediately
suspicious as an outlier compared to peers.

## Step 2 — Encoded Command Detection
Query 02 returned 16 events across 11 distinct command lines. Every result contained
powershell.exe invoked with -NoP -NonI -W Hidden -enc flags followed by Base64-encoded
payloads. The -W Hidden flag suppresses the PowerShell window entirely, confirming
deliberate evasion. One entry showed schtasks.exe creating a scheduled task pointing
back to powershell.exe — indicating persistence establishment.

## Step 3 — Parent/Child Process Analysis
Query 03 analyzed 9,212 process creation events and surfaced 176 unique parent-child
relationships. Top suspicious chains:
- cmd.exe → WMIC.exe: 966 occurrences
- cmd.exe → WMIC.exe (lateral): 476 occurrences  
- cmd.exe → reg.exe: 461 occurrences

cmd.exe spawning WMIC.exe and reg.exe are classic Living off the Land patterns used
for WMI-based lateral movement and registry persistence respectively.

## MITRE Mapping
| Technique | ID | Evidence |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | -enc flag, -W Hidden, 16 events |
| Obfuscated Files or Information | T1027 | Base64-encoded payloads in all 11 cmd lines |
| Scheduled Task/Job | T1053.005 | schtasks.exe creating PowerShell persistence |
| Living off the Land | T1218 | cmd.exe → WMIC.exe (476), cmd.exe → reg.exe (461) |
