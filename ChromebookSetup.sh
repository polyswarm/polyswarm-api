#!/bin/bash


echo "deb http://ftp.us.debian.org/debian testing main" | sudo tee -a /etc/apt/sources.list

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install python3.6
sudo dpkg --configure -a
sudo apt-get install -y python3-pip
pip3 install polyswarm-api

echo "PATH="$HOME/.local/bin:$PATH" | sudo tee -a $HOME/.profile
. $HOME/.profile