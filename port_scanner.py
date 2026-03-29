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
parser.add_argument("--ports", default="22",
                    help="desired port(s) to scan, use '-' for a range. ex: 10-18 ")
parser.add_argument("--timeout", default=0.5,
                    help="Default time before giving up on a connection")
parser.add_argument("--output", default="JSON",
                    help="Receive output in JSON file")
args = parser.parse_args()

#Scan Settings...
TARGET = args.host
DESIRED_PORTS = args.ports
TIMEOUT = args.timeout 

def get_ports(ports_str):
    if "-" in ports_str:
        P1, P2 = ports_str.split("-")
        return range(int(P1), int(P2) + 1) #Potential hazard later on (+1)?
    return int(ports_str)


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

if __name__ == "__main__":
    ip = socket.getaddrinfo(TARGET, None, socket.AF_INET)[0][4][0]
    if isinstance(get_ports(DESIRED_PORTS), range):
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(lambda portX: scan_port(TARGET, portX), get_ports(DESIRED_PORTS))
        for port, result in results:
            if result:
                print(f"Port {port} at IP {ip} is open. Service -> {socket.getservbyport(port)}")
            else:
                string1 = f"Port {port} at IP {ip} is closed. "
                if getPortResult(TARGET, port) == errno.ECONNREFUSED:
                    string2 = f"Connection Refused (Closed)" #TODO Test if this works
                else:
                    string2 =f"Connection attempt filtered or timed out."
            print(string1 + string2)

    else:
        result = scan_port(TARGET, int(DESIRED_PORTS))
        if result[1] == True: #Port is Open
            print(f"Port {DESIRED_PORTS} at IP {TARGET} is open. Service -> {socket.getservbyport(int(DESIRED_PORTS))}")
        elif result == errno.ECONNREFUSED:
            print(f"Connection Refused (Closed)")
        else:
            print(f"Connection attempt filtered or timed out.")
       


    #     for port in get_ports(DESIRED_PORTS):
    #         print(F"Look at {port}")

    # result = scan_port(TARGET, int(PORTS))
    # if result[1] == True:
    #     print(f"Port {PORTS} at IP {ip} is open. Service -> {socket.getservbyport(int(PORTS))}")
    # else:
    #     print(f"Port {PORTS} at IP {ip} is closed")
    #     if result[1] == errno.ECONNREFUSED:
    #         print(f"Connection Refused (Closed)") #TODO Test if this works
    #     else:
    #         print(f"Connection attempt filtered or timed out.")