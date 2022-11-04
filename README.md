![Screenshot](/logo/CrabLogo.png)
# Crab

Crab is an open source network scanning tool for tracking, gathering information, and scanning a host.

Crab can complete multiple tasks such as port scanning, ip look ups, whois registar info, and OS detection(beta).


# Disclaimer

I am not responsible for whoever uses this program unlawfully. 

This project is open source and anyone can use it/edit it.

# Installation

To install crab you will need 

- Python3 or up
- pip
- git

Clone Crab onto your machine

```
git clone https://gitub.com/N0tA1dan/crab
```
Next cd into the directory

```
cd crab
```
Then cd into the src directory

```
cd src
```
Install the requirements

```
pip install -r requirements.txt
```
Finally run the file

```
python crab.py
```

# Usage

To list all the commands type the command below in a terminal

```
python crab.py -h
```

Now the port scanning can get a bit tricky

```
python crab.py -sA [your target] [timeout in seconds]
```
We need the timeout in seconds because the program goes really fast and uses a lot of processing power. 
I personally use 0.5 second time out but it may vary from systems. 
If you have a weak computer, increase the timeout.
