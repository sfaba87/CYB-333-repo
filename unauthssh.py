#Created by: Shane Fababier
#Date last modified: 06-27-24
#Program Summary: Analyzes failed ssh logins from journalctl in Fedora. Sends alert for multiple failures. 
import os
import tkinter as tk
from tkinter import messagebox

def unauthorized_ssh_logins():
    try:
        cmd = "journalctl _COMM=sshd --since yesterday"
        output = os.popen(cmd).read()
        #Reads journalctl log. Change time frame as needed.

        unauthorized_logins = {}

        for line in output.splitlines():
            if "Failed password" in line:
                log_info = line.split()
                #Parses log_info in journalctl to get time, source IP, and User.
                timestamp = " ".join(log_info[0:3])
                source_ip = log_info[-4]
                username = log_info[-6]

                #Records last SSH login failure and counts number of failures.
                if username in unauthorized_logins:
                    unauthorized_logins[username] = (timestamp, source_ip, unauthorized_logins[username][2] + 1)
                else:
                    unauthorized_logins[username] = (timestamp, source_ip, 1)

        #Checks users with multiple ssh login failures. Change number of failures as needed.
        user_mult_fail = {username: data for username, data in unauthorized_logins.items() if data[2] > 5}

        #Prints all ssh login failures in terminal.
        print("All unauthorized SSH login attempts:")
        for username, data in unauthorized_logins.items():
            timestamp, source_ip, count = data
            print(f"Username: {username}")
            print(f"  Timestamp: {timestamp}, Source IP: {source_ip}")
            print(f"  Total Failed Attempts: {count}")
            print("-------------------")

        if user_mult_fail:
            #Message box for user with multiple failed logins.
            alert_msg = "Unauthorized SSH login attempts:\n"
            for username, data in user_mult_fail.items():
                timestamp, source_ip, count = data
                alert_msg += f"Username: {username}\n"
                alert_msg += f"  Last Attempt: Timestamp: {timestamp}, Source IP: {source_ip}\n"
                alert_msg += f"  Total Failed Attempts: {count}\n"

            #Displays pop-up window showing users with multiple login failures. 
            msg_win = tk.Tk()
            msg_win.withdraw()
            messagebox.showwarning("Security Alert: Please Take Action.", alert_msg)
            print(alert_msg)

        else:
            print("No unusual events.")

    except IOError:
        print(f"Error reading log file")

if __name__ == "__main__":
    unauthorized_ssh_logins()