#!/bin/bash
set -e

if [ -n "$RESTORE_FROM_FILE" ] && [ -f "$RESTORE_FROM_FILE" ]; then
    echo "Restore file found at $RESTORE_FROM_FILE. Starting database restoration..."
    pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" -1 --no-owner --no-privileges "$RESTORE_FROM_FILE"
    echo "Database restoration complete."
else
    echo "RESTORE_FROM_FILE not set or file not found. Starting with a new, empty database."
fi