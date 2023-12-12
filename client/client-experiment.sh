#!/usr/bin/env bash

# check if the script is running with root privileges
if [[ $EUID -ne 0 ]]; then
	echo "Please use sudo to run the script with root privileges"
	exit 1
fi

TIMESTAMP=$(date +%Y%m%d%H%M%S)
# HOSTNAME="example"
HOSTNAME="wikipedia"
CAPTURE_OUTPUT_DIRECTORY="captures"
CAPTURE_OUTPUT_FILE_PCAP="$CAPTURE_OUTPUT_DIRECTORY/client-tcpdump-$TIMESTAMP-$HOSTNAME.pcap"
CAPTURE_OUTPUT_FILE_LOCAL_PCAP="$CAPTURE_OUTPUT_DIRECTORY/client-tcpdump-$TIMESTAMP-$HOSTNAME-local.pcap"
CAPTURE_OUTPUT_FILE_TXT="$CAPTURE_OUTPUT_DIRECTORY/client-tcpdump-$TIMESTAMP-$HOSTNAME.txt"
LOG_OUTPUT_DIRECTORY="logs"
LOG_OUTPUT_FILE="$LOG_OUTPUT_DIRECTORY/client-log-$TIMESTAMP-$HOSTNAME.log"
USER="rajat"
INTERFACE="enp0s8"
WEBSITE="https://en.$HOSTNAME.org"
# WEBSITE="https://www.$HOSTNAME.com"

TIMEOUT_CAPTURE_OUTPUT_FILE_PCAP="$CAPTURE_OUTPUT_DIRECTORY/timeout/client-tcpdump-$TIMESTAMP-$HOSTNAME.pcap"
TIMEOUT_CAPTURE_OUTPUT_FILE_LOCAL_PCAP="$CAPTURE_OUTPUT_DIRECTORY/timeout/client-tcpdump-$TIMESTAMP-$HOSTNAME.pcap"
TIMEOUT_LOG_OUTPUT_FILE="$LOG_OUTPUT_DIRECTORY/timeout/client-log-$TIMESTAMP-$HOSTNAME.log"


OUS_RATE=3
FIREFOX_DELAY=30

function cleanup() {
	echo "Killing all child processes..."
	pkill -P $$ # terminate all child process of the script's PID
	unset SSLKEYLOGFILE
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
tcpdump -i lo -w "$CAPTURE_OUTPUT_FILE_LOCAL_PCAP" > /dev/null 2>&1 &
TCPDUMP_PID_LOCAL_PCAP=$!
# tcpdump -i "$INTERFACE" -X -n > "$CAPTURE_OUTPUT_FILE_TXT" 2>&1 &
# TCPDUMP_PID_TXT=$!

echo "OUS_RATE=$OUS_RATE" >> $LOG_OUTPUT_FILE
echo "FIREFOX_DELAY=$FIREFOX_DELAY" >> $LOG_OUTPUT_FILE

echo "Log file $(realpath "$LOG_OUTPUT_FILE")"

sleep_countdown 5

echo "Starting python client.py"
python client.py &>> $LOG_OUTPUT_FILE &
PYTHON_PID=$!

echo "Deleting Firefox cache directory"
FIREFOX_PROFILE="egwcx94s.default-release"
rm -rf "/home/rajat/.cache/mozilla/firefox/$FIREFOX_PROFILE/cache2/*"

sleep_countdown $FIREFOX_DELAY

TIMEOUT_SECONDS=180

echo "Loading $WEBSITE on Firefox with $TIMEOUT_SECONDS seconds timeout..."
timeout "$TIMEOUT_SECONDS" su -c "firefox --devtools $WEBSITE" "$USER" > /dev/null 2>&1 &
FIREFOX_PID=$!

wait $FIREFOX_PID

FIREFOX_EXIT_STATUS=$?

if [ "$FIREFOX_EXIT_STATUS" -eq 124 ]; then
	echo "Firefox terminated due to the timeout"
	# echo "Deleting latest logs..."
	echo "Moving latest logs to timeout directory..."
	mv "$LOG_OUTPUT_FILE" "$TIMEOUT_LOG_OUTPUT_FILE"
	mv "$CAPTURE_OUTPUT_FILE_PCAP" "$TIMEOUT_CAPTURE_OUTPUT_FILE_PCAP"
	mv "$CAPTURE_OUTPUT_FILE_LOCAL_PCAP" "$TIMEOUT_CAPTURE_OUTPUT_FILE_LOCAL_PCAP"
	# rm "$LOG_OUTPUT_FILE"
	# rm "$CAPTURE_OUTPUT_FILE_PCAP"
	# rm "$CAPTURE_OUTPUT_FILE_TXT"
else
	echo "Firefox terminated normally"
fi

sleep_countdown 30

kill -INT $$

