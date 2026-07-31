#!/bin/bash

SOURCE_DIR="/home/x3no21/git/DistributedAuthenticationPUF"
DESTINATION="raspberrypi5@iotlabvr.ddns.net:/home/raspberrypi5/Documents/DistributedAuthenticationPUF"

echo "Starting real-time synchronization..."

while inotifywait -r --exclude '(build/|\.git/|venv/)' -e modify,create,delete,move "$SOURCE_DIR"; do
    rsync -avz --exclude 'build' --exclude '.git' --exclude 'venv' "$SOURCE_DIR/" "$DESTINATION"
    echo "Synchronization complete. Waiting for new changes..."
done
