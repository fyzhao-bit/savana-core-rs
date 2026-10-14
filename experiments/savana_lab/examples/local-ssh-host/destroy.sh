#!/bin/bash
# SshHosts' destroy command for the local stand-in machine ($SAVANA_LAB_HOST is its address).
set -euo pipefail
docker rm -f savana-lab-ssh >/dev/null
