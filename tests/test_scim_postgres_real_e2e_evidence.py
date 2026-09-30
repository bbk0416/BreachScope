from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "external_baseline" / "scim_postgres_real_e2e_20260930.yaml"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_real_postgres_e2e_evidence_is_bound_to_current_fix() -> None:
    row = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))
    assert row["schema"] == "breachscope.scim_postgres_real_e2e.v1"
    assert row["status"] == "PASS"
    assert row["environment"]["postgres_server_version"] == "16.15"
    assert row["environment"]["psycopg_version"] == "3.3.5"
    assert row["environment"]["cluster_isolation"] == "ephemeral_localhost_only"
    assert row["environment"]["system_postgres_service_modified"] is False

    for binding in row["source_binding"].values():
        assert _sha(ROOT / binding["path"]) == binding["sha256"]


def test_real_postgres_e2e_exercised_storage_locking_and_migration() -> None:
    result = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))["result"]
    assert result["initdb"] == "PASS"
    assert result["server_start"] == "PASS"
    assert result["real_schema_tables"] == 3
    assert result["cross_instance_shared_state"] == "PASS"
    assert result["repeatable_read_snapshot"] == "PASS"
    assert result["transaction_rollback"] == "PASS"
    assert result["advisory_lock_two_store_serialization"] == "PASS"
    assert result["advisory_lock_max_simultaneous_critical_sections"] == 1
    assert result["real_advisory_lock_function"] == "PASS"
    assert result["sqlite_to_postgres_migration"] == "PASS"
    assert result["migration_digest_verified"] is True
    assert result["server_stop"] == "PASS"
    assert result["cluster_path_removed"] is True


def test_real_postgres_e2e_claim_boundary_stays_narrow() -> None:
    claims = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))["claim_boundary"]
    assert claims["actual_real_postgresql_server_e2e"] is True
    assert claims["actual_postgresql_write_path_exercised"] is True
    assert claims["actual_postgresql_group_membership_path_exercised"] is True
    assert claims["actual_postgresql_advisory_lock_exercised"] is True
    assert claims["actual_sqlite_to_postgresql_migration_exercised"] is True
    assert claims["multi_host_postgresql_ha"] == "NOT_TESTED"
    assert claims["managed_cloud_postgresql"] == "NOT_TESTED"
    assert claims["cross_machine_breachscope_replicas"] == "NOT_TESTED"
    assert claims["production_load"] == "NOT_TESTED"
    assert claims["backup_restore"] == "NOT_TESTED"
    assert claims["credential_rotation"] == "NOT_TESTED"
