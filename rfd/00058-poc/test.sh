#!/bin/bash

apt_source_file="/etc/apt/sources.list.d/aptly-local.list"
screen_name="aptly"
key_name="Test Signingkey"

echo "Configuring apt..."
echo "deb http://localhost:8080/ubuntu focal non-free/stable/v8" > "$apt_source_file"
gpg1 --armor --export "$key_name" | apt-key add -
screen -S "$screen_name" -dm aptly serve
sleep 1
echo
echo "Running apt update..."
apt update
echo
echo "Available Teleport versions:"
apt-cache policy teleport
echo
echo "Total repo size: `du -sh ${HOME}/.aptly/public | cut -d $'\t' -f1`"
echo
echo "Cleaning up..."
screen -S "$screen_name" -X quit
apt-key remove "$key_name"
rm "$apt_source_file"
