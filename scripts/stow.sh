#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <directory>"
    exit 1
fi

SRC_DIR=$1

for file in "$SRC_DIR"/*.sh; do
    base_file=$(basename "$file")
    target_file="$HOME/$base_file"

    if [ -f "$target_file" ]; then
        echo "Deleting $target_file from $HOME"
        rm -f "$target_file"
    fi
done

echo "Symlinking files from $SRC_DIR to $HOME"
stow -t "$HOME" "$SRC_DIR"
