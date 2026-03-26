#!/bin/bash
set -euo pipefail

# @REMOTE sui
# @SHELL zsh
sudo pacman -Syyu --noconfirm
paru -Syyu --noconfirm
rustup update
sudo podman auto-update
mise install go@latest
