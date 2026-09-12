from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

DAY1_SOURCE_TECHNIQUES = [
    'T1002','T1003','T1005','T1016','T1018','T1022','T1027','T1028','T1032','T1033',
    'T1035','T1036','T1041','T1043','T1045','T1048','T1050','T1056','T1057','T1059',
    'T1060','T1063','T1065','T1069','T1071','T1074','T1077','T1078','T1081','T1082',
    'T1083','T1086','T1088','T1105','T1106','T1107','T1112','T1113','T1115','T1119',
    'T1122','T1134','T1140','T1145','T1204'
]


def sha256(path: Path) -> str:
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    return h


def attack_id(obj: dict) -> str | None:
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack' and ref.get('external_id'):
            return str(ref['external_id']).upper()
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--stix', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    p = Path(args.stix)
    data = json.loads(p.read_text(encoding='utf-8'))

    by_id: dict[str, list[dict]] = {}
    for obj in data.get('objects', []):
        if obj.get('type') != 'attack-pattern':
            continue
        ext = attack_id(obj)
        if ext:
            by_id.setdefault(ext, []).append(obj)

    active=[]; inactive=[]; missing=[]
    for tid in DAY1_SOURCE_TECHNIQUES:
        objs=by_id.get(tid, [])
        if not objs:
            missing.append(tid)
            continue
        rows=[]
        any_active=False
        for o in objs:
            row={
                'name': o.get('name'),
                'stix_id': o.get('id'),
                'revoked': bool(o.get('revoked', False)),
                'deprecated': bool(o.get('x_mitre_deprecated', False)),
                'is_subtechnique': bool(o.get('x_mitre_is_subtechnique', False)),
            }
            rows.append(row)
            if not row['revoked'] and not row['deprecated']:
                any_active=True
        target={'technique_id':tid,'objects':rows}
        (active if any_active else inactive).append(target)

    result={
        'schema':'breachscope.p2_12b_attack_v19_2_active_id_binding.v1',
        'attack_source':{
            'repository':'mitre-attack/attack-stix-data',
            'pinned_commit':'6cda5ad8462c79e14fbb872f4e09059b18e0cfc4',
            'release':'Enterprise ATT&CK v19.2',
            'path':'enterprise-attack/enterprise-attack-19.2.json',
            'sha256':sha256(p),
        },
        'source_day1_technique_count':len(DAY1_SOURCE_TECHNIQUES),
        'source_day1_techniques':DAY1_SOURCE_TECHNIQUES,
        'active_exact_ids':[x['technique_id'] for x in active],
        'active_exact_id_count':len(active),
        'inactive_exact_ids':[x['technique_id'] for x in inactive],
        'inactive_exact_id_count':len(inactive),
        'missing_exact_ids':missing,
        'missing_exact_id_count':len(missing),
        'details':{'active':active,'inactive':inactive},
        'scoring_policy':{
            'primary_denominator':'active_exact_ids_only',
            'legacy_inactive_or_missing_ids':'reported_separately_not_silently_remapped',
            'detector_results_consulted':False,
            'detector_executed':False,
        },
    }
    Path(args.out).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ['active_exact_id_count','active_exact_ids','inactive_exact_id_count','inactive_exact_ids','missing_exact_id_count','missing_exact_ids']},indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
