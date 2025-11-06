import socket
import uuid
import re
import subprocess

def getIP():
    hostname = socket.gethostname()
    ipAddress = socket.gethostbyname(hostname)
    return ipAddress

def getMAC():
    mac = (':'.join(re.findall('..', '%012x' % uuid.getnode())))
    return mac

def dashboard():
    while True:
        print("Digital Forensics Tool Dashboard")
        print("================================")
        print("(1) Get IP Address")
        print("(2) Get MAC Address")
        print("(3) Exit")

        choice = input("Pick an option: ")

        if choice == "1":

          ip = getIP()
          print(" ")
          print("Your IP Address is: " , ip)
          print(" ")

        elif choice == "2":

            mac = getMAC()
            print(" ")
            print("Your MAC Address is: " , mac)
            print(" ")

        elif choice == "3":
            print(" ")
            print("Exiting...")
            print(" ")
            break

        else:
            print(" ")
            print("Invalid choice. Please try again.")
            print(" ")


if __name__ == "__main__":
    
    dashboard()

