import requests
import sys
import whois
import threading
import socket
import time

args = sys.argv[1:]

print('''\033[1;31;1m
   ______           __
  / ____/________ _/ /_
 / /   / ___/ __ `/ __ |
/ /___/ /  / /_/ / /_/ /
\____/_/   \__,_/_.___/    By NotAidan.
''')


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
    -i: Info - Get Basic information on a given Host/IP. Its basically a IP scanner.
    -w: whois - Runs a whois search on a given Host
        ''')
    if (args[0] == "-i"):
        iplookup(args[1])
    if (args[0] == "-w"):
        pytonwhois(args[1])
    if (args[0] == "-sA"):
        portscan2(args[1], args[2])
    if (args[0] == "-sC"):
        fastportscan(args[1], args[2])

except IndexError:
    print("Invalid args. Use [-h] for help")
