#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <number_of_runs>"
    exit 1
fi

number_of_runs="$1"

for ((i = 1; i <= number_of_runs; i++)); do
    echo "RUNNING EXPERIMENT $i..."
    
    tmux send-keys -t waterfall:0.1 "./decoy-experiment.sh" C-m 
    bash "./client-experiment.sh"
    tmux send-keys -t waterfall:0.1 C-c

    echo "COMPLETED EXPERIMENT $i"
done

echo "ALL EXPERIMENTS COMPLETED"
