FROM postgres:15

ENV POSTGRES_USER=raft
# Overridden at run time by start_postgres.sh; set POSTGRES_PASSWORD in the
# environment before starting the container.
ENV POSTGRES_PASSWORD=CHANGE_ME
ENV POSTGRES_DB=logger_db

COPY init-db.sh /docker-entrypoint-initdb.d/
RUN chmod +x /docker-entrypoint-initdb.d/init-db.sh