# BreachScope built-in demo scenarios

이 폴더의 JSONL은 실제 침해 데이터가 아니라 BreachScope 시연/테스트용 합성 로그입니다.
도메인은 example.local, 파일명은 demo/simulated 값을 사용합니다.

| ID | Name | Events | Expected Techniques |
|---|---|---:|---|
| `powershell_downloader` | PowerShell downloader and encoded execution | 4 | T1059.001, T1105 |
| `credential_dump_triage` | Credential dump triage | 5 | T1003.001, T1003.002, T1003.003 |
| `ransomware_preparation` | Ransomware preparation | 5 | T1490, T1562.001, T1070.001 |
| `lateral_movement_remote_admin` | Remote administration lateral movement | 4 | T1021.006, T1569.002, T1543.003, T1047 |
| `active_directory_discovery` | Active Directory discovery sweep | 7 | T1087.001, T1087.002, T1482, T1135, T1057, T1518.001 |
| `lolbin_proxy_execution` | LOLBins proxy execution cluster | 7 | T1218.005, T1218.011, T1218.010, T1218.003, T1127.001, T1218.004, T1202 |
| `cloud_exfiltration_staging` | Cloud exfiltration staging | 4 | T1560.001, T1567.002 |
| `persistence_mechanisms` | Persistence mechanisms | 4 | T1547.001, T1053.005, T1543.003 |
| `defense_evasion_controls` | Defense evasion control changes | 4 | T1562.001, T1562.002, T1562.004 |
| `user_data_collection` | User data collection | 4 | T1555.003, T1115, T1113, T1560.001 |

## Run

```bash
python scripts/run.py --input samples/scenarios --export-json --export-csv
python scripts/run.py --demo-scenario ransomware_preparation --export-json --export-csv
```
