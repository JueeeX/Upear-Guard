#!/bin/sh
set -eu

: "${SAFEHARNESS_BACKUP_DIR:=/backups}"
: "${SAFEHARNESS_BACKUP_RETENTION_DAYS:=30}"
: "${SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN:?set PostgreSQL DSN}"

umask 077
mkdir -p "$SAFEHARNESS_BACKUP_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
target="$SAFEHARNESS_BACKUP_DIR/safeharness-audit-$timestamp.dump"
partial="$target.partial"
checksum="$target.sha256"
schema_version_file="$target.schema-version"

cleanup_partial() {
  rm -f "$partial" "$checksum.partial" "$schema_version_file.partial"
}
trap cleanup_partial EXIT INT TERM

schema_version="$(
  psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
    --command="SELECT version FROM safeharness_schema WHERE component = 'postgres_audit'" \
    "$SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN"
)"
case "$schema_version" in
  ''|*[!0-9]*)
    printf '%s\n' 'SafeHarness backup refused an invalid schema version.' >&2
    exit 1
    ;;
esac

pg_dump --format=custom --no-owner --no-acl --data-only \
  --table=safeharness_audit_records \
  --file="$partial" \
  "$SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN"
pg_restore --list "$partial" | grep -q 'TABLE DATA.*safeharness_audit_records'
sha256sum "$partial" | awk '{print $1}' >"$checksum.partial"
printf '%s\n' "$schema_version" >"$schema_version_file.partial"
mv "$partial" "$target"
mv "$checksum.partial" "$checksum"
mv "$schema_version_file.partial" "$schema_version_file"
trap - EXIT INT TERM

find "$SAFEHARNESS_BACKUP_DIR" -type f \
  \( -name 'safeharness-audit-*.dump' \
     -o -name 'safeharness-audit-*.dump.sha256' \
     -o -name 'safeharness-audit-*.dump.schema-version' \) \
  -mtime "+$SAFEHARNESS_BACKUP_RETENTION_DAYS" -delete

printf '%s\n' "$target"
