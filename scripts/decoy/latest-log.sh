#!/bin/bash

log_directory="/home/rajat/github/waterfall/decoy/logs"

if [ ! -d "$log_directory" ]; then
    echo "Directory not found: $log_directory"
    exit 1
fi

latest_log_file=$(find "$log_directory" -type f -name "*.log" -exec stat --format='%Y %n' {} \; | sort -n | tail -n 1 | awk '{print $2}')

if [ -z "$latest_log_file" ]; then
    echo "No .log files found in $log_directory"
    exit 1
fi

echo "Tailing the latest .log file: $latest_log_file"
tail -f "$latest_log_file"
