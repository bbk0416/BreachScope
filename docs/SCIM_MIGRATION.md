# SCIM Identity Store Migration

BreachScope can migrate deployment-wide SCIM Users, Groups, and nested membership state between the `json`, `sqlite`, and `postgres` identity backends.

The migration tool is intended for a maintenance window. It does not freeze an IdP or another running BreachScope replica. Pause SCIM provisioning and other identity writes before the final migration, keep them paused through the configuration cutover, then resume only after the new backend passes the operational checks.

## Safety behavior

- The source store is read only. Migration never writes to the source backend.
- `--dry-run` validates the source and inspects the target without creating an empty SQLite target database or initializing PostgreSQL SCIM tables.
- A non-empty target is rejected unless `--replace` is explicit.
- `--replace` writes a normalized JSON snapshot of the previous target identity state before overwriting it.
- The backup contains identity metadata such as user names, OIDC `externalId`, role, organization, and group membership. Protect the backup like other identity data.
- PostgreSQL URLs are read only from environment variables. They are not accepted as literal CLI values and are not emitted in result JSON.
- SQLite/PostgreSQL target writes use one store mutation transaction.
- JSON target writes preserve the original file bytes and restore them if a write or post-write verification fails.
- After writing, the tool re-reads the target and compares a canonical SHA-256 digest with the source snapshot.
- Switching backends does not delete the old source. Keep it until the new backend has been verified.

## Commands

The installed wheel exposes:

~~~bash
breachscope-scim-migrate --help
~~~

The module form works with the installed wheel or a source checkout:

~~~bash
python -m breachscope.scim_migrate --help
~~~

A source checkout also provides:

~~~bash
python scripts/scim_store_migrate.py --help
~~~

### JSON -> SQLite

Dry-run first:

~~~bash
python -m breachscope.scim_migrate \
  --source-backend json \
  --target-backend sqlite \
  --source-user-path ~/.breachscope/scim_users.json \
  --source-group-path ~/.breachscope/scim_groups.json \
  --target-database-path ~/.breachscope/scim_identity.db \
  --dry-run
~~~

If the result is valid, rerun without `--dry-run`.

### SQLite -> PostgreSQL

Do not place the PostgreSQL URL directly on the command line. Put it in an environment variable.

PowerShell example:

~~~powershell
$env:BS_SCIM_TARGET_DATABASE_URL = "<postgresql-connection-url>"

python -m breachscope.scim_migrate `
  --source-backend sqlite `
  --target-backend postgres `
  --source-database-path "$HOME\.breachscope\scim_identity.db" `
  --target-database-url-env BS_SCIM_TARGET_DATABASE_URL `
  --dry-run
~~~

Then run the same command without `--dry-run`.

For PostgreSQL as the source, use `BS_SCIM_SOURCE_DATABASE_URL` or pass another environment-variable name with `--source-database-url-env`.

### Replace a non-empty target

Replacement is deliberately explicit:

~~~bash
python -m breachscope.scim_migrate \
  --source-backend sqlite \
  --target-backend json \
  --source-database-path ~/.breachscope/scim_identity.db \
  --target-user-path ~/.breachscope/scim_users.json \
  --target-group-path ~/.breachscope/scim_groups.json \
  --replace \
  --backup-dir ~/.breachscope/scim-migration-backups
~~~

Without `--replace`, a non-empty target fails before any target write.

## Cutover checklist

1. Stop or pause upstream SCIM provisioning and any manual identity changes.
2. Run the migration with `--dry-run`.
3. Run the migration for real.
4. Record the reported source/target SHA-256 and backup path when one is created.
5. Change `BS_SCIM_STORAGE_BACKEND` and the matching path/URL configuration.
6. Restart BreachScope instances with the new configuration.
7. Run:

~~~bash
python scripts/go_live_check.py --deployment-mode production
~~~

8. Confirm a known OIDC+SCIM user can authenticate with the expected organization and role.
9. Resume provisioning.
10. Retain the old source store and migration backup until the cutover is accepted.

For a multi-replica deployment, move all replicas to the same PostgreSQL target. Do not split active replicas across old and new SCIM backends during the cutover.
