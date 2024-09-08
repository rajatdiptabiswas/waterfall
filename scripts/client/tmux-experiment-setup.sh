#!/usr/bin/env bash


sleep_countdown() {
	local seconds=$1

    if [ "$seconds" -le 0 ]; then
        return
    fi
	
	echo "Waiting $seconds seconds..."
	
    for (( i=seconds; i>=1; i-- )) do
		printf "\r%s\033[K" "$i"
		sleep 1
	done

	printf "\r\033[K"
}


tmux_send_keys() {
    local target="$1"
    local keys="$2"
    local sleep_time="$3"

    tmux send-keys -t "$target" "$keys" C-m
    sleep_countdown "$sleep_time"
}


echo "Starting decoy tmux terminal window"
tmux new-session -d -s experiment

tmux_send_keys experiment:0 "cd ~" 1
echo "SSH into decoy VM"
tmux_send_keys experiment:0 "./ssh-decoy.sh" 2
echo "Getting superuser access"
tmux_send_keys experiment:0 "su" 2
tmux_send_keys experiment:0 "waterfall" 2
echo "Starting decoy setup script"
tmux_send_keys experiment:0 ". setup.sh" 0


echo "Starting client tmux terminal window"
tmux split-window -h -t experiment:0

tmux_send_keys experiment:0 "cd ~" 1
echo "Getting superuser access"
tmux_send_keys experiment:0 "su" 2
tmux_send_keys experiment:0 "waterfall" 2
echo "Running client setup script"
tmux_send_keys experiment:0 ". setup.sh" 0


tmux attach
