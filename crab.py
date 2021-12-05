import requests
import sys
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


try:
    if(args[0] == "-h"):
        print('''Usage: python3 crab.py [Options] {Target}

    -h: Shows this menu
    -ps: Port Scan - Scans open ports for a given Host
    -i: Info - Get Basic information on a given Host
    -w: whois - Runs a whois search on a given Host

        ''')
    if(args[0] == "-i"):
        iplookup(args[1])

except IndexError:
    print("Invalid args. Use [-h] for help")
