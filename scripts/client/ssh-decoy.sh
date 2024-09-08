#!/bin/bash

# SSH connection details
SSH_USER="rajat"
SSH_HOST="10.0.2.16"
SSH_PORT="22"
SSH_PASSWORD="waterfall"

# SSH command using sshpass
sshpass -p "$SSH_PASSWORD" ssh -p "$SSH_PORT" "$SSH_USER@$SSH_HOST"

