#!/bin/sh
set -eu

: "${SAFEHARNESS_BACKUP_DIR:=/backups}"
: "${PGHOST:?set PostgreSQL host}"
: "${PGUSER:?set PostgreSQL administrator user}"
: "${PGPASSWORD:?set PostgreSQL administrator password}"
: "${PGDATABASE:=safeharness}"

backup="$(
  find "$SAFEHARNESS_BACKUP_DIR" -maxdepth 1 -type f \
    -name 'safeharness-audit-*.dump' -print | sort | tail -n 1
)"
if [ -z "$backup" ]; then
  printf '%s\n' 'SafeHarness restore check found no backup archive.' >&2
  exit 1
fi

checksum_file="$backup.sha256"
schema_version_file="$backup.schema-version"
if [ ! -f "$checksum_file" ] || [ ! -f "$schema_version_file" ]; then
  printf '%s\n' 'SafeHarness restore check requires checksum and schema metadata.' >&2
  exit 1
fi

expected_checksum="$(tr -d '[:space:]' <"$checksum_file")"
expected_schema_version="$(tr -d '[:space:]' <"$schema_version_file")"
case "$expected_checksum" in
  *[!0-9a-fA-F]*|'')
    printf '%s\n' 'SafeHarness backup checksum metadata is invalid.' >&2
    exit 1
    ;;
esac
if [ "${#expected_checksum}" -ne 64 ]; then
  printf '%s\n' 'SafeHarness backup checksum metadata is invalid.' >&2
  exit 1
fi
case "$expected_schema_version" in
  ''|*[!0-9]*)
    printf '%s\n' 'SafeHarness backup schema metadata is invalid.' >&2
    exit 1
    ;;
esac

actual_checksum="$(sha256sum "$backup" | awk '{print $1}')"
if [ "$actual_checksum" != "$expected_checksum" ]; then
  printf '%s\n' 'SafeHarness backup checksum verification failed.' >&2
  exit 1
fi
pg_restore --list "$backup" | grep -q 'TABLE DATA.*safeharness_audit_records'

restore_database="safeharness_restore_check_$(date -u +%Y%m%d%H%M%S)_$$"
case "$restore_database" in
  safeharness_restore_check_[0-9]*) ;;
  *)
    printf '%s\n' 'Unsafe restore database name.' >&2
    exit 1
    ;;
esac

cleanup_database() {
  case "$restore_database" in
    safeharness_restore_check_[0-9]*)
      dropdb --if-exists --force "$restore_database" >/dev/null 2>&1 || true
      ;;
  esac
}
trap cleanup_database EXIT INT TERM

createdb "$restore_database"
SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN="postgresql://$PGUSER:$PGPASSWORD@$PGHOST:${PGPORT:-5432}/$restore_database" \
  SAFEHARNESS_TOOL_GATEWAY_POSTGRES_RUNTIME_ROLE='' \
  SAFEHARNESS_TOOL_GATEWAY_POSTGRES_READER_ROLE='' \
  safeharness-postgres-init >/dev/null

current_schema_version="$(
  psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
    --dbname="$restore_database" \
    --command="SELECT version FROM safeharness_schema WHERE component = 'postgres_audit'"
)"
if [ "$current_schema_version" != "$expected_schema_version" ]; then
  printf '%s\n' 'SafeHarness backup schema version does not match this release.' >&2
  exit 1
fi

pg_restore --exit-on-error --single-transaction --data-only --no-owner --no-acl \
  --dbname="$restore_database" "$backup"
restored_rows="$(
  psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
    --dbname="$restore_database" \
    --command='SELECT count(*) FROM safeharness_audit_records'
)"
case "$restored_rows" in
  ''|*[!0-9]*)
    printf '%s\n' 'SafeHarness restored audit row count is invalid.' >&2
    exit 1
    ;;
esac

if [ "$restored_rows" -eq 0 ]; then
  psql --no-psqlrc --quiet --set ON_ERROR_STOP=1 --dbname="$restore_database" \
    --command="
      INSERT INTO safeharness_audit_records (
        record_id, source, record_type, action, outcome, occurred_at,
        tenant_id, agent_id, session_id, run_id, trace_id, event_id,
        sequence, tool_name, tool_version, tool_integrity_digest,
        invocation_digest, capability_fingerprint, decision_id, receipt_id,
        disposition, reason_code, request_id, payload_json
      ) VALUES (
        'restore-check', 'restore-check', 'gateway', 'restore_check', 'test', now(),
        '', '', '', '', '', '', 0, '', '', '', '', '', '', '', '', '', '', '{}'::jsonb
      )" >/dev/null
fi

if psql --no-psqlrc --quiet --set ON_ERROR_STOP=1 --dbname="$restore_database" \
  --command="
    UPDATE safeharness_audit_records SET outcome = outcome
    WHERE audit_id = (SELECT min(audit_id) FROM safeharness_audit_records)" \
  >/dev/null 2>&1; then
  printf '%s\n' 'SafeHarness restored audit mutation trigger did not fail closed.' >&2
  exit 1
fi

cleanup_database
trap - EXIT INT TERM
printf 'SafeHarness PostgreSQL restore check passed: %s audit rows.\n' "$restored_rows"
