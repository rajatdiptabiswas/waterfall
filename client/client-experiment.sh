#!/usr/bin/env bash

# check if the script is running with root privileges
if [[ $EUID -ne 0 ]]; then
	echo "Please use sudo to run the script with root privileges"
	exit 1
fi

TIMESTAMP=$(date +%Y%m%d%H%M%S)
HOSTNAME="wikipedia"
CAPTURE_OUTPUT_DIRECTORY="captures"
CAPTURE_OUTPUT_FILE="$CAPTURE_OUTPUT_DIRECTORY/tcpdump-$TIMESTAMP-$HOSTNAME.pcap"
LOG_OUTPUT_DIRECTORY="logs"
LOG_OUTPUT_FILE="$LOG_OUTPUT_DIRECTORY/log-$TIMESTAMP-$HOSTNAME.log"
USER="rajat"
INTERFACE="enp0s8"
WEBSITE="https://en.$HOSTNAME.org"

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
tcpdump -i "$INTERFACE" -w "$CAPTURE_OUTPUT_FILE" > /dev/null 2>&1 &
TCPDUMP_PID=$!

sleep_countdown 5

echo "Starting python client.py"
python client.py &> $LOG_OUTPUT_FILE &
PYTHON_PID=$!

sleep_countdown 10

# echo "Starting Firefox..."
# su -c "firefox" "$USER" > /dev/null 2>&1 &

# sleep_countdown 20

echo "Loading $WEBSITE on Firefox..."
su -c "firefox $WEBSITE" "$USER" > /dev/null 2>&1 &



watch -n 1 "tail -n 15 $LOG_OUTPUT_FILE"

wait
