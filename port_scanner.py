#port_scanner.py

#Build the PORT SCANNER. Flags: --host, --ports (range or list), --timeout, --output JSON. Uses ThreadPoolExecutor for concurrency. 
# Reports open ports with service name. Handles connection refused vs timeout differently.
import argparse
import socket, errno
from concurrent.futures import ThreadPoolExecutor

#Setting up Argument Parser...
parser = argparse.ArgumentParser(description="Port Scanner")
parser.add_argument("--host", default="scanme.nmap.org",
                    help="IP/Host we would like to scan against")
parser.add_argument("--ports", default=22,
                    help="desired port(s) to scan")
parser.add_argument("--timeout", default=0.5,
                    help="Default time before giving up on a connection")
parser.add_argument("--output", default="JSON",
                    help="Receive output in JSON file")
args = parser.parse_args()

#Scan Settings...
TARGET = args.host
PORTS = args.ports
TIMEOUT = args.timeout 

def scan_port(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        result = s.connect_ex((host, port))
        is_open = result == 0
    return port, is_open

if __name__ == "__main__":
    ip = socket.getaddrinfo("scanme.nmap.org", None, socket.AF_INET)[0][4][0]
    result = scan_port(TARGET, int(PORTS))
    if result[1] == True:
        print(f"Port {PORTS} at IP {ip} is open. Service -> {socket.getservbyport(int(PORTS))}")
    else:
        print(f"Port {PORTS} at IP {ip} is closed")
        if result[1] == errno.ECONNREFUSED:
            print(f"Connection Refused (Closed)") #TODO Test if this works
        else:
            print(f"Connection attempt filtered or timed out.")