FROM postgres:17-alpine

RUN mkdir -p /backups \
    && touch /backups/.keep \
    && chown -R postgres:postgres /backups
COPY --chown=postgres:postgres --chmod=0555 deploy/postgres/backup.sh /opt/safeharness/backup.sh

USER postgres
ENTRYPOINT ["sh", "/opt/safeharness/backup.sh"]
