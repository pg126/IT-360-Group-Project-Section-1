import platform # To get system information (OS, version, architecture)
import socket # To get hostname and IP address
import uuid # To get MAC address
import re # For formating MAC address
import subprocess # Subprocess module to run system commands (tasklist, powershell commands)
import winreg  #   Windows Registry access(Default Browser)


# Functions to get system IP Address
def getIP():
    hostname = socket.gethostname()     # Get machine hostname
    ipAddress = socket.gethostbyname(hostname) # Get IP address using hostname
    return ipAddress

# Function to get MAC Address
def getMAC():
    mac = (':'.join(re.findall('..', '%012x' % uuid.getnode()))) # Format MAC address to XX:XX:XX:XX:XX:XX
    return mac

# Function to get System Information
def getSystemInfo():
    operatingSystem = platform.system() # Get OS name
    version = platform.version() # Get OS version
    release = platform.release() # Get OS release
    architecture = platform.machine() # Get system architecture (x86, x64)
    hostname = platform.node() # Get system hostname

    # Return system information as a dictionary
    return {"Operating System: ": operatingSystem , 
            "Version": version , 
            "Release": release , 
            "Architecture": architecture , 
            "Hostname": hostname}

# Function to get Running Processes
def getRunningProcesses():
    try:
        result = subprocess.check_output(["tasklist"], shell=True, text=True)
        lines = result.strip().split("\n")[3:] # Skip header lines
        return lines[:-1]  # Return all lines
    except Exception as e:
        return "Error"

# Function to get Installed Applications
def getApplications():
    try:
        # PowerShell command to get installed applications from registry
        powershell_cmd = ( 
            "powershell \"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
            "Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize\""
        )
        result = subprocess.check_output(powershell_cmd, shell=True, text=True) # Run PowerShell command to get installed applications
        lines = result.strip().split("\n")[3:] # Skip header lines
        software_list = [line.strip() for line in lines if line.strip()] #Clean up output
        return software_list
    except Exception as e:
        return [f"Error retrieving software list: {e}"]

# Function to get Startup Programs
def getStartupPrograms():
    try:
        # PowerShell command to get startup programs
        powershellCMD = (
            'powershell "Get-CimInstance -ClassName Win32_StartupCommand | '
            'Select-Object Name, Command, Location | Format-Table -AutoSize"'
        )
        result = subprocess.check_output(powershellCMD, shell=True, text=True) # Run PowerShell command to get startup programs
        lines = result.strip().split('\n')[3:] # Skip header lines
        startup_list = [line.strip() for line in lines if line.strip()] # Clean up output
        return startup_list
    except Exception as e:
        return [f"Error retrieving startup programs: {e}"]

# Function to get Recent Event Logs
def getEventLogs():
    try:
        # PowerShell command to get recent event logs
        powershellCMD = (
            'powershell "Get-EventLog -LogName System -Newest 10 | '
            'Select-Object TimeGenerated, EntryType, Source, EventID, Message | Format-Table -AutoSize"'
        )
        result = subprocess.check_output(powershellCMD, shell=True, text=True) # Run PowerShell command to get recent event logs
        lines = result.strip().split('\n')[3:] # Skip header lines
        eventLogs = [line.strip() for line in lines if line.strip()] # Clean up output
        return eventLogs
   
    except Exception as e:
        return [f"Error retrieving recent Event Logs: {e}"]

# Function to get Default Browser
def getDefaultBrowser():
    path = r'SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' # Registry path for default browser
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key: # Open registry key
        browserID = winreg.QueryValueEx(key, "ProgID")[0] # Get ProgID value
        defaultBrowser = browserID.split("-")[0] # Extract browser name from ProgID
        return defaultBrowser


# Dashboard function to display menu and handle user input
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
        print("(9) Exit")

        choice = input("Pick an option: ")

        # Handle user choice
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
           

# Main function to start the dashboard
if __name__ == "__main__":
    
    dashboard()
