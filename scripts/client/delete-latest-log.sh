#!/bin/bash

log_directory="/home/rajat/github/waterfall/client/logs"
pcap_directory="/home/rajat/github/waterfall/client/captures"

if [ ! -d "$log_directory" ]; then
    echo "Directory not found: $log_directory"
    exit 1
fi

if [ ! -d "$pcap_directory" ]; then
    echo "Directory not found: $pcap_directory"
    exit 1
fi

latest_log_file=$(find "$log_directory" -type f -name "*.log" -exec stat --format='%Y %n' {} \; | sort -n | tail -n 1 | awk '{print $2}')
latest_pcap_file=$(find "$pcap_directory" -type f -name "*.pcap" -exec stat --format='%Y %n' {} \; | sort -n | tail -n 1 | awk '{print $2}')

if [ -z "$latest_log_file" ]; then
    echo "No .log files found in $log_directory"
    exit 1
fi

if [ -z "$latest_pcap_file" ]; then
    echo "No .pcap files found in $pcap_directory"
    exit 1
fi

echo "Removing the latest .log file $latest_log_file and .pcap file $latest_pcap_file"
rm "$latest_log_file"
rm "$latest_pcap_file"
