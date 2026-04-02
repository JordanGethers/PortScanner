#port_scanner.py

#Build the PORT SCANNER. Flags: --host, --ports (range or list), --timeout, --output JSON. Uses ThreadPoolExecutor for concurrency. 
# Reports open ports with service name. Handles connection refused vs timeout differently.
import argparse, json
import socket, errno
from concurrent.futures import ThreadPoolExecutor
from enum import Enum

#Setting up Argument Parser...
parser = argparse.ArgumentParser(description="Port Scanner")
parser.add_argument("--host", default="scanme.nmap.org",
                    help="IP/Host we would like to scan against")
parser.add_argument("--ports", default="22",
                    help="desired port(s) to scan, use '-' for a range. ex: 10-18 ")
parser.add_argument("--timeout", default=0.5,
                    help="Default time before giving up on a connection")
parser.add_argument("--output", default="JSON",
                    help="Receive output in JSON file") #TODO: Revisit this later
args = parser.parse_args()

#Scan Settings...
TARGET = args.host
DESIRED_PORTS = args.ports
TIMEOUT = args.timeout 

class PortStatus(Enum):
    OPEN = "Open"
    CLOSED = "Closed"
    FILTERED = "Filtered/Timeout"

def get_ports(ports_str):
    if "-" in ports_str:
        P1, P2 = ports_str.split("-")
        return range(int(P1), int(P2) + 1) #Potential hazard later on (+1)?
    return [int(ports_str)]


def scan_port(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        result = s.connect_ex((host, port))
        is_open = result == 0
    return port, is_open

def getPortResult(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        result = s.connect_ex((host, port))
        return result
    
def printReport(output):
    open_ports = 0
    closed_ports = 0
    filtered_ports = 0
    for x in range(0, len(output['port_report'])):
        if output['port_report'][x].get("status") == "Open":
            open_ports += 1
        elif output['port_report'][x].get("status") == "Closed":
            closed_ports += 1
        else:
            filtered_ports += 1

    print(f"Port Scanning report for {TARGET}")
    print(f"{open_ports} open ports")
    print(f"{closed_ports} closed ports")
    print(f"{filtered_ports} ports filtered/timed out\n")

    print(f"{'PORT':<10}{'STATUS':<20}{'SERVICE':<20}")
    print("-" * 50)

    for entry in output['port_report']:
        if entry['status'] == PortStatus.OPEN.value:
            print(f"{entry['port']:<10}{entry['status']:<20}{entry['service']:<20}")




if __name__ == "__main__":
    IP = socket.getaddrinfo(TARGET, None, socket.AF_INET)[0][4][0]
    output = {"Host":TARGET, "port_report":[]}

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda portX: scan_port(TARGET, portX), get_ports(DESIRED_PORTS))
    for port, result in results:
        if result:
            output["port_report"].append({"port":port, "status":PortStatus("Open").value,
                                            "service":socket.getservbyport(port)})            
        else:
            if getPortResult(TARGET, port) == errno.ECONNREFUSED:
                output["port_report"].append({"port":port, "status":PortStatus("Closed").value,
                                                "service":"null"})
            else:
                output["port_report"].append({"port":port, "status":PortStatus("Filtered/Timeout").value,
                                                "service":"null"})           

    printReport(output)  