#!/bin/sh
set -eu

: "${SAFEHARNESS_REDIS_PASSWORD:?set Redis administrator password}"
: "${SAFEHARNESS_REDIS_GATEWAY_PASSWORD:?set Redis gateway password}"
: "${SAFEHARNESS_REDIS_COMMUNICATION_PASSWORD:?set Redis communication password}"

acl_file=/tmp/users.acl
umask 077
cat >"$acl_file" <<EOF
user default off
user safeharness_admin on >${SAFEHARNESS_REDIS_PASSWORD} ~* &* +@all
user safeharness_gateway on >${SAFEHARNESS_REDIS_GATEWAY_PASSWORD} ~safeharness:capability-replay:* ~safeharness:receipt-replay:* &* -@all +set +ping +quit
user safeharness_communication on >${SAFEHARNESS_REDIS_COMMUNICATION_PASSWORD} ~safeharness:communication-rate:* &* -@all +incr +pexpireat +multi +exec +ping +quit
EOF

exec redis-server \
  --appendonly yes \
  --appendfsync everysec \
  --save "" \
  --aclfile "$acl_file" \
  --protected-mode yes
