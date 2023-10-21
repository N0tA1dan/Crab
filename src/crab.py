import requests
import sys
import whois
import threading
import socket
import time
from scapy.all import *
import json

args = sys.argv[1:]

print('''\033[1;31;1m
   ______           __
  / ____/________ _/ /_
 / /   / ___/ __ `/ __ |
/ /___/ /  / /_/ / /_/ /
\____/_/   \__,_/_.___/    By NotAidan.
''')

def generate_new_filename(filename):
    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(f"{base} ({counter}){ext}"):
        counter += 1
    return f"{base} ({counter}){ext}"


def censysHostLookup(host):
    headers = {
        'Accept': 'application/json',
    }

    params = {
        'q': f'{host}',
    }

    response = requests.get(
        'https://search.censys.io/api/v2/hosts/search',
        params=params,
        headers=headers,

        # PUT YOUR API ID AND API KEY HERE IF YOU WANT TO USE CENSYS
        auth=(os.getenv('CENSYS_API_ID', 'API_ID_HERE'), os.getenv('CENSYS_API_SECRET', 'API_SECRET_HERE')),
    )
    
    filename = "CensysData.txt"
    new_filename = generate_new_filename(filename)
    f = open(new_filename, "a+")
    f.write(json.dumps(response.json(), indent=2))
    f.close()

    print(f"Check CensysData.txt for the logs or go to https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q={host}")



# os detection using ttl values in a icmp request
def icmpOSD(host):

    print("\033[1;33;1m-----------------------------------")
    try:
        print("Attempting to send ping...")
        icmp = sr1(IP(dst=f"{host}")/ICMP(), verbose=0)
        ttl = icmp.ttl

        if(ttl == 128):
            print("Windows OS detected. ttl = 128")
        elif(ttl == 64):
            print("Linux/Unix Detected. ttl = 64")
        else:
            print(f"TTL is unrecognized. ttl = {ttl}")

    except Exception as e:
        print(f"error has occured: {e}")


def iplookup(host):
    print("\033[1;33;1m-----------------------------------")
    print("\033[1;36;1mResults for", host + "\n")
    ipsearch = requests.get("http://ip-api.com/json/" + host).json()
    print("Country:", ipsearch['country'])
    print("State:", ipsearch['regionName'])
    print("City:", ipsearch['city'])
    print("Zip:", ipsearch['zip'])
    print("Latitude:", ipsearch['lat'])
    print("Longitude:", ipsearch['lon'])
    print("Timezone:", ipsearch['timezone'])
    print("ISP:", ipsearch['isp'])
    print("Organization:", ipsearch['org'])


def pytonwhois(host):
    w = whois.whois(host)
    print(w.text)


def portscan(host, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(float(timeout))

    try:
        con = s.connect((host, port))
        print('Port:', port, "is open.   Service ---> ", socket.getservbyport(port))
        con.close()
    except:
        pass


def portscan2(host, timeout):
    start = time.time()
    for x in range(0, 65536):
        t = threading.Thread(target=portscan, kwargs={'host': host, 'port': x, 'timeout': timeout})

        x += 1
        t.start()
    end = time.time()
    print("took: ", end - start, "seconds")




def fastportscan(host, timeout):
    start = time.time()
    for x in range(0, 1025):
        t = threading.Thread(target=portscan, kwargs={'host': host, 'port': x, 'timeout': timeout})

        x += 1
        t.start()
    end = time.time()
    print("took: ", end - start, "seconds")


try:
    if (args[0] == "-h"):
        print('''Usage: python crab.py [Options] {Target}
    -h: Shows this menu
              
    -sA: Port Scan All - Casual port scan. Scans every port on a given host.
        Usage: python crab.py -sA [host] [time out in seconds]
        Example: python crab.py -sA google.com 0.5
              
    -sC: Port scan common - Fastest port scan. Only scans from a range of 1 - 1024
        Usage: python crab.py -sC [host] [time out in seconds]
        Example: python crab.py -sC google.com 0.5
              
    -pD: Ping Detection - this command uses icmp requests and analyzes the ttl to derive an OS.
        --- WARNING --- ping detection might not work unless ran with elevated permissions
        Usage: python crab.py -pD [host]
        Example: python crab.py -pD 1.1.1.1
              
    -i: Info - Get Basic information on a given Host/IP. Its basically a IP scanner.
              
    -w: whois - Runs a whois search on a given Host
              
    -cS: Censys Lookup - This will run a given domain/host against Censys and obtain good information. REMEMBER TO PLACE YOUR API ID AND API SECRET INTO THE MAIN FILE (crab.py) AROUND LINE 36
        Usage: python crab.py -cS [host]
        ''')
    if (args[0] == "-i"):
        iplookup(args[1])
    if (args[0] == "-w"):
        pytonwhois(args[1])
    if (args[0] == "-sA"):
        portscan2(args[1], args[2])
    if (args[0] == "-sC"):
        fastportscan(args[1], args[2])
    if (args[0] == "-pD"):
        icmpOSD(args[1])
    if (args[0] == "-cS"):
        censysHostLookup(args[1])

except IndexError:
    print("Invalid args. Use [-h] for help")

