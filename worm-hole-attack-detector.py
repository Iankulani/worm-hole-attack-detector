# -*- coding: utf-8 -*-
"""
Created on Tue Feb  27 08:345:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Worm Hole Attack Detector")
print(Fore.GREEN+font)

import subprocess
import re
import os

def ping_ip(ip_address):
    """
    Ping the provided IP address to check for high latency or irregular behavior.
    """
    try:
        # Run the ping command (using 4 packets for a quick test)
        if os.name == 'nt':  # For Windows
            response = subprocess.run(["ping", "-n", "4", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:  # For Linux or MacOS
            response = subprocess.run(["ping", "-c", "4", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Check if the ping was successful and parse the output
        output = response.stdout.decode()

        # Parse the output for average latency information
        avg_latency = parse_avg_latency(output)

        return avg_latency
    except Exception as e:
        print(f"Error pinging IP: {e}")
        return None

def parse_avg_latency(output):
    """
    Parse the output of the ping command to get the average latency.
    """
    match = re.search(r"avg = (\d+\.\d+) ms", output)
    if match:
        return float(match.group(1))
    return None

def traceroute(ip_address):
    """
    Perform a traceroute to the given IP address to identify unusual routing paths.
    """
    try:
        # Run the traceroute command
        if os.name == 'nt':  # For Windows
            command = ["tracert", ip_address]
        else:  # For Linux or MacOS
            command = ["traceroute", ip_address]

        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = response.stdout.decode()

        return output
    except Exception as e:
        print(f"Error performing traceroute: {e}")
        return None

def detect_wormhole(avg_latency, traceroute_output):
    """
    Check if there are signs of a wormhole attack based on abnormal latency or routing behavior.
    """
    # Check if latency is excessively high (this could be a sign of a wormhole)
    if avg_latency is not None and avg_latency > 200:  # Arbitrary threshold of 200 ms for high latency
        print(f"Warning: High latency detected! Average latency: {avg_latency} ms. This may indicate a wormhole attack.")
    
    # Analyze the traceroute output for abnormal routing paths
    if traceroute_output:
        print("Traceroute Output:\n" + traceroute_output)
        if "Request Timed Out" in traceroute_output:
            print("Warning: Request timeout in traceroute. This could indicate routing anomalies.")
        else:
            # Check if any hop repeats which could be an indicator of a wormhole
            hops = traceroute_output.split("\n")
            unique_hops = set()
            for hop in hops:
                if hop:
                    ip = hop.split()[1] if len(hop.split()) > 1 else None
                    if ip and ip in unique_hops:
                        print(f"Warning: Duplicate hop detected: {ip}. This might suggest a wormhole attack.")
                    unique_hops.add(ip)

def main():
    
    print("This tool checks if an IP address might be associated with a Wormhole attack by analyzing latency and routing behavior.")

    while True:
        # Prompt user to input an IP address
        ip_address = input("Enter the IP address to check (or 'exit' to quit):").strip()

        if ip_address.lower() == 'exit':
            print("Exiting the tool. Goodbye!")
            break

        # Ping the IP address to get the average latency
        print(f"Checking network latency for IP address: {ip_address}")
        avg_latency = ping_ip(ip_address)

        if avg_latency is None:
            print("Error: Could not retrieve ping data. Please check the IP address and try again.")
        else:
            print(f"Average Latency: {avg_latency} ms")

        # Perform a traceroute to check for abnormal routing
        print(f"Performing traceroute to IP address: {ip_address}")
        traceroute_output = traceroute(ip_address)

        if traceroute_output:
            # Detect potential wormhole behavior
            detect_wormhole(avg_latency, traceroute_output)
        else:
            print("Error: Could not retrieve traceroute data.")

if __name__ == "__main__":
    main()
