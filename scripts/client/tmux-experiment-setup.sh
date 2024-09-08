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


echo "Starting client|decoy tmux terminal window"
tmux new-session -d -s waterfall
tmux split-window -h -t waterfall:0

echo "Starting decoy setup"
tmux_send_keys waterfall:0.1 "cd ~" 2
echo "SSH into decoy VM"
tmux_send_keys waterfall:0.1 "./ssh-decoy.sh" 5
echo "Getting superuser access"
tmux_send_keys waterfall:0.1 "su" 5
tmux_send_keys waterfall:0.1 "waterfall" 5
echo "Running decoy setup script"
tmux_send_keys waterfall:0.1 ". setup.sh" 5

echo "Starting client setup"
tmux_send_keys waterfall:0.0 "cd ~" 2
echo "Getting superuser access"
tmux_send_keys waterfall:0.0 "su" 5
tmux_send_keys waterfall:0.0 "waterfall" 5
echo "Running client setup script"
tmux_send_keys waterfall:0.0 ". setup.sh" 5

tmux attach
