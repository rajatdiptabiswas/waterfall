#!/bin/bash

# Directory where snapshots will be saved
snapshot_dir="/home/rajat/htop"

# Time interval in seconds between snapshots
interval=60

while true; do
    timestamp=$(date +"%Y%m%d%H%M%S")
    echo q | htop | aha --black --line-fix > "$snapshot_dir/htop_snapshot_$timestamp.html"
    echo "Took htop snapshot $timestamp"
    sleep "$interval"
done
