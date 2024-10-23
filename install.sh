#!/bin/bash

echo "[+] Updating package list..."
sudo apt-get update

echo "[+] Installing Python3..."
sudo apt-get install -y python3

echo "[+] Installing pip for Python3..."
sudo apt-get install -y python3-pip

echo "[+] Installing Python modules: wmi, subprocess, datetime..."
pip3 install wmi subprocess datetime

echo "[+] Installing common system tools: net-tools, curl, wget, auditd..."
sudo apt-get install -y net-tools curl wget auditd

echo "[+] Installing PowerShell..."
sudo apt-get install -y powershell

echo "[+] Installing Windows compatibility libraries (Wine)..."
sudo apt-get install -y wine

echo "[+] Installing Firewall (iptables)..."
sudo apt-get install -y iptables

echo "[+] Installing cert-utils and firewall..."
sudo apt-get install -y  iptables 


