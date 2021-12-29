import requests
import sys
import whois
import threading
import socket



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


def portscan(host, port):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)#

    try:
        con = s.connect((host,port))

        print('Port :',port,"is open.")

        con.close()
    except:
        pass

def portscan2(host):
    r = 1
    for x in range(1,10000):

        t = threading.Thread(target=portscan,kwargs={'host':host, 'port': r})

        r += 1
        t.start()



try:
    if (args[0] == "-h"):
        print('''Usage: python3 crab.py [Options] {Target}
    -h: Shows this menu
    -ps: Port Scan - Scans open ports for a given Host
    -i: Info - Get Basic information on a given Host
    -w: whois - Runs a whois search on a given Host
        ''')
    if (args[0] == "-i"):
        iplookup(args[1])
    if (args[0] == "-w"):
        pytonwhois(args[1])
    if(args[0] == "-p"):
        portscan2(args[1])

except IndexError:
    print("Invalid args. Use [-h] for help")
