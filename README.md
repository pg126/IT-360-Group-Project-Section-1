# Digital Forensics Tool

This project is a Windows-based digital forensics tool developed in Python. It collects system information that can support basic forensic investigations through a simple command-line dashboard.

## Features

1. Get IP Address  
2. Get MAC Address  
3. Get Default Browser  
4. Get System Information  
5. Get Running Processes  
6. Get Installed Applications  
7. Get Startup Programs  
8. Get Recent Event Logs

## How the Tool Works

The tool displays a menu and allows the user to select what type of data to gather. Each option calls a specific function that retrieves system information using built-in Python modules such as `platform`, `socket`, `uuid`, `subprocess`, and `winreg`. These modules allow the tool to interact with Windows system components, PowerShell commands, and registry keys.

No external Python packages are required.

## How to Run

1. Install Python on Windows.  
2. Open Command Prompt and navigate to the folder containing the script.  
3. Run the tool with:

py DigitalForensicsTool.py

csharp
Copy code

## Purpose of the Project

The goal of this tool is to automate basic forensic data collection on a Windows machine. Instead of manually running multiple commands, this tool centralizes tasks such as checking system information, processes, installed software, startup items, and event logs, helping investigators gather evidence more efficiently.

## Video Demonstration

Insert your video link here.
