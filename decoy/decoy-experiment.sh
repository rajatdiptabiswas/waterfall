#!/usr/bin/env bash

# check if the script is running with root privileges
if [[ $EUID -ne 0 ]]; then
	echo "Please use sudo to run the script with root privileges"
	exit 1
fi

TIMESTAMP=$(date +%Y%m%d%H%M%S)
HOSTNAME="example"
# HOSTNAME="wikipedia"
CAPTURE_OUTPUT_DIRECTORY="captures"
CAPTURE_OUTPUT_FILE_PCAP="$CAPTURE_OUTPUT_DIRECTORY/decoy-tcpdump-$TIMESTAMP-$HOSTNAME.pcap"
CAPTURE_OUTPUT_FILE_TXT="$CAPTURE_OUTPUT_DIRECTORY/decoy-tcpdump-$TIMESTAMP-$HOSTNAME.txt"
LOG_OUTPUT_DIRECTORY="logs"
LOG_OUTPUT_FILE="$LOG_OUTPUT_DIRECTORY/decoy-log-$TIMESTAMP-$HOSTNAME.log"
INTERFACE="br0"

function cleanup() {
	echo "Killing all child processes..."
	pkill -P $$ # terminate all child process of the script's PID
	echo "Cleanup complete"
	exit
}

function sleep_countdown() {
	local seconds=$1

	echo "Waiting $seconds seconds..."
	
	for (( i=seconds; i>=1; i-- )) do
		printf "\r%s\033[K" "$i" #`\r` moves cursor to the beginning of the line without advancing to the next line, `\033[K` clears the characters from the current cursor position to the end of the line
		sleep 1
	done

	printf "\r\033[K"
}

trap cleanup SIGINT # call `cleanup` function when sending the SIGINT Ctrl+C command

mkdir -p $CAPTURE_OUTPUT_DIRECTORY
mkdir -p $LOG_OUTPUT_DIRECTORY

echo "Starting tcpdump..."
tcpdump -i "$INTERFACE" -w "$CAPTURE_OUTPUT_FILE_PCAP" > /dev/null 2>&1 &
TCPDUMP_PID_PCAP=$!
# tcpdump -i "$INTERFACE" -X -n > "$CAPTURE_OUTPUT_FILE_TXT" 2>&1 &
# TCPDUMP_PID_TXT=$!

sleep_countdown 5

echo "Starting python capturepackets.py"
python capturepackets.py &>> $LOG_OUTPUT_FILE &
PYTHON_PID=$!

echo "Log file $(realpath "$LOG_OUTPUT_FILE")"

wait
