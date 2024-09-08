#!/bin/bash

directories=(
    "./captures"
    "./logs"
)

latest_timestamp=$(find ${directories[@]} -type f -printf "%T+ %p\n" | sort -r | head -n 1 | cut -d' ' -f2- | grep -oP '\d{14}')

if [ -z "$latest_timestamp" ]; then
    echo "Latest timestamp extraction failed"
    exit 1
fi

echo "The following files will be deleted"
find ${directories[@]} -type f -name "*$latest_timestamp*"

read -p "Are you sure you want to delete these files? (y/n) " confirmation

if [[ $confirmation =~ ^[Yy]$ ]]; then
    find "${directories[@]}" -type f -name "*$latest_timestamp*" -print0 | xargs -0 rm -v
    echo "Files have been deleted"
else
    echo "File deletion cancelled"
    exit 0
fi
