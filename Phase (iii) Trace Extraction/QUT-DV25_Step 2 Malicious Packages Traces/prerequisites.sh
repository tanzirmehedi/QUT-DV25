#!/bin/bash

echo "-------------------------------------------Step 0-------------------------------------------------------------"
echo "Updating package list..."
sudo apt-get update

echo "-------------------------------------------Step 1-------------------------------------------------------------"
echo "Installing Python and pip..."
sudo apt-get install -y python3 python3-pip

echo "-------------------------------------------Step 2-------------------------------------------------------------"
echo "Installing BCC and Linux kernel headers..."
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r)

echo "-------------------------------------------Step 3-------------------------------------------------------------"
echo "Installing Linux kernel tools..."
sudo apt-get install -y linux-tools-$(uname -r)

echo "-------------------------------------------Step 4-------------------------------------------------------------"
echo "Checking BPF tool version and kernel version..."
bpftool --version
uname -r

echo "-------------------------------------------Step 5-------------------------------------------------------------"
echo "Installing bpftrace..."
sudo apt-get install -y bpftrace

echo "-------------------------------------------Step 6-------------------------------------------------------------"
echo "Checking bpftrace version..."
bpftrace --version

echo "-------------------------------------------Step 7-------------------------------------------------------------"
echo "Setting up virtualenv with --break-system-packages option..."
pip3 install virtualenv --break-system-packages

echo "-------------------------------------------Step 8-------------------------------------------------------------"
echo "All prerequisites installed successfully."