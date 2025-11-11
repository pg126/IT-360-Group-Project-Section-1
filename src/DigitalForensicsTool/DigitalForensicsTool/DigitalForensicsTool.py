import platform
import socket
from sys import version
from unittest import result
import uuid
import re
import subprocess
import winreg


def getIP():
    hostname = socket.gethostname()
    ipAddress = socket.gethostbyname(hostname)
    return ipAddress

def getMAC():
    mac = (':'.join(re.findall('..', '%012x' % uuid.getnode())))
    return mac

def getSystemInfo():
    operatingSystem = platform.system()
    version = platform.version()
    release = platform.release()
    architecture = platform.machine()
    hostname = platform.node()

    return {"Operating System: ": operatingSystem , 
            "Version": version , 
            "Release": release , 
            "Architecture": architecture , 
            "Hostname": hostname}

def getRunningProcesses():
    try:
        result = subprocess.check_output(["tasklist"], shell=True, text=True)
        lines = result.strip().split("\n")[3:]  
        return lines[:-1]  
    except Exception as e:
        return [f"Error: {e}"]

def getApplications():
    try:
        powershell_cmd = (
            "powershell \"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
            "Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize\""
        )
        result = subprocess.check_output(powershell_cmd, shell=True, text=True)
        lines = result.strip().split("\n")[3:]
        software_list = [line.strip() for line in lines if line.strip()]
        return software_list
    except Exception as e:
        return [f"Error retrieving software list: {e}"]

def getStartupPrograms():
    try:
        powershellCMD = (
            'powershell "Get-CimInstance -ClassName Win32_StartupCommand | '
            'Select-Object Name, Command, Location | Format-Table -AutoSize"'
        )
        result = subprocess.check_output(powershellCMD, shell=True, text=True)
        lines = result.strip().split('\n')[3:] 
        startup_list = [line.strip() for line in lines if line.strip()]
        return startup_list
    except Exception as e:
        return [f"Error retrieving startup programs: {e}"]

def getEventLogs():
    try:
        powershellCMD = (
            'powershell "Get-EventLog -LogName System -Newest 10 | '
            'Select-Object TimeGenerated, EntryType, Source, EventID, Message | Format-Table -AutoSize"'
        )
        result = subprocess.check_output(powershellCMD, shell=True, text=True)
        lines = result.strip().split('\n')[3:] 
        eventLogs = [line.strip() for line in lines if line.strip()]
        return eventLogs
   
    except Exception as e:
        return [f"Error retrieving recent Event Logs: {e}"]


def getDefaultBrowser():
    path = r'SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice'
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
        browserID = winreg.QueryValueEx(key, "ProgID")[0]
        defaultBrowser = browserID.split("-")[0]
        return defaultBrowser



def dashboard():
    while True:
        print("Digital Forensics Tool Dashboard")
        print("================================")
        print("(1) Get IP Address")
        print("(2) Get MAC Address")
        print("(3) Get Default Browser")
        print("(4) Get System Info")
        print("(5) Get Running Processes")
        print("(6) Get Installed Applications")
        print("(7) Get Startup Programs")
        print("(8) Get Recent Event Logs")
        print("(8) Exit")

        choice = input("Pick an option: ")

        if choice == "1":

          ip = getIP()
          print("\nYour IP Address is: " , ip , "\n")
         

        elif choice == "2":

            mac = getMAC()
            print("\nYour MAC Address is: " , mac , "\n")
            

        elif choice == "3":
            browser = getDefaultBrowser()
            print("\nYour Default Browser is: " , browser , "\n")
            
        elif choice == "4":
            systemInfo = getSystemInfo()
            print("\n===System Information===\n")
            for key, value in systemInfo.items():
                print(f"{key}: {value}\n")
           

        elif choice == "5":
            processes = getRunningProcesses()
            print("\n===Running Processes===")
            for process in processes:
                print(process)
            print(" ")

        elif choice == "6":
            installedApplications = getApplications()
            print("\n===Installed Applications===\n")
            for app in installedApplications:
                print(app)
            print(" ")

        elif choice == "7":
            startupPrograms = getStartupPrograms()
            print("\n===Startup Programs===\n")
            for program in startupPrograms:
                print(program)
            print(" ")

        elif choice == "8":
            eventLogs = getEventLogs()
            print("\n===Recent Event Logs===\n")
            for log in eventLogs:
                print(log)
            print(" ")

        elif choice == "9":
            print("\nExiting Digital Forensics Tool. Goodbye!\n")
            break

        else:
            print("\nInvalid choice. Please try again.\n")
           


if __name__ == "__main__":
    
    dashboard()



