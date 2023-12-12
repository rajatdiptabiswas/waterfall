#!/bin/bash


# List of directories where you want to delete the latest logs
directories=(
    "./captures"
    "./logs"
)

# Iterate through the directories
for dir in "${directories[@]}"; do
    # Check if the directory exists
    if [ ! -d "$dir" ]; then
        echo "Directory not found: $dir"
        continue  # Move to the next directory if this one doesn't exist
    fi

    # Change to the directory
    cd "$dir" || continue  # Move to the next directory if CD fails

    # List files in the directory by modification time, with the latest first
    latest_file=$(ls -t | head -n 1)

    # Check if a file was found
    if [ -z "$latest" ]; then
        echo "No files found in $dir."
    else
        # Delete the latest file
        rm "$latest"
        echo "Deleted the latest file in $dir: $latest"
    fi
done

