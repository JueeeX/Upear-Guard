#!/bin/sh
set -eu

psql --set ON_ERROR_STOP=1 \
  --set migrator_password="$SAFEHARNESS_POSTGRES_MIGRATOR_PASSWORD" \
  --set writer_password="$SAFEHARNESS_POSTGRES_WRITER_PASSWORD" \
  --set reader_password="$SAFEHARNESS_POSTGRES_READER_PASSWORD" \
  --set retention_password="$SAFEHARNESS_POSTGRES_RETENTION_PASSWORD" \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE safeharness_migrator LOGIN PASSWORD :'migrator_password';
CREATE ROLE safeharness_writer LOGIN PASSWORD :'writer_password';
CREATE ROLE safeharness_reader LOGIN PASSWORD :'reader_password';
CREATE ROLE safeharness_retention LOGIN PASSWORD :'retention_password';

REVOKE ALL ON DATABASE safeharness FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE safeharness
    TO safeharness_migrator, safeharness_writer, safeharness_reader, safeharness_retention;
GRANT USAGE, CREATE ON SCHEMA public TO safeharness_migrator;
GRANT USAGE ON SCHEMA public
    TO safeharness_writer, safeharness_reader, safeharness_retention;
SQL
