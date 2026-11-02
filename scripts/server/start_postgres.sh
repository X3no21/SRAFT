#!/bin/bash

set -e

IMAGE_NAME="postgres-monitoring"
CONTAINER_NAME="pg_server"
DB_USER="${POSTGRES_USER:-raft}"
DB_PASSWORD="${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD before running this script}"
HOST_PORT="5432"
DATA_VOLUME_FRESH="pg_data_fresh"
DATA_VOLUME_RESTORED="pg_data_restored"

if [ "$(docker ps -a -q -f name=$CONTAINER_NAME)" ]; then
    echo "Stopping and removing existing container: $CONTAINER_NAME"
    docker stop $CONTAINER_NAME >/dev/null 2>&1
    docker rm $CONTAINER_NAME >/dev/null 2>&1
fi

if [ "$#" -eq 1 ]; then
    RESTORE_FILE_HOST_PATH="$1"
    if [ ! -f "$RESTORE_FILE_HOST_PATH" ]; then
        echo "Error: Restore file not found at '$RESTORE_FILE_HOST_PATH'"
        exit 1
    fi

    RESTORE_FILE_BASENAME=$(basename "$RESTORE_FILE_HOST_PATH")
    echo "Starting container in RESTORE mode from file: $RESTORE_FILE_HOST_PATH"

   docker run -d --name $CONTAINER_NAME \
      -e POSTGRES_USER="$DB_USER" \
      -e POSTGRES_PASSWORD="$DB_PASSWORD" \
      -e RESTORE_FROM_FILE="/backups/$RESTORE_FILE_BASENAME" \
      -p "$HOST_PORT:5432" \
      -v "$DATA_VOLUME_RESTORED:/var/lib/postgresql/data" \
      -v "$(pwd)/db_backups:/backups" \
      "$IMAGE_NAME"

else
    echo "Starting container in FRESH DATABASE mode."
    docker run -d --name $CONTAINER_NAME \
      -e POSTGRES_USER="$DB_USER" \
      -e POSTGRES_PASSWORD="$DB_PASSWORD" \
      -p "$HOST_PORT:5432" \
      -v "$DATA_VOLUME_FRESH:/var/lib/postgresql/data" \
      "$IMAGE_NAME"
fi

echo "Container '$CONTAINER_NAME' started successfully."
echo "Waiting a few seconds for the database to be ready..."
sleep 5
docker logs $CONTAINER_NAME