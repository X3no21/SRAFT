#!/bin/bash

# Root of this checkout, two levels above this script.
SOURCE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DESTINATION="pi@raspberrypi.local:/home/pi/Documents/git/SRAFT"

echo "Starting real-time synchronization..."

while inotifywait -r --exclude '(build/|\.git/|venv/)' -e modify,create,delete,move "$SOURCE_DIR"; do
    rsync -avz --exclude 'build' --exclude '.git' --exclude 'venv' "$SOURCE_DIR/" "$DESTINATION"
    echo "Synchronization complete. Waiting for new changes..."
done
