import logging
import sys
import datetime
import certstream
import argparse
import time
FAIL        = '\033[91m'
ENDC        = '\033[0m'
OKGREEN     = '\033[92m'
BOLD        = '\033[1m'
OKBLUE      = '\033[94m'
WARNING     = '\033[93m'
GREY        = '\033[90m'
PURPLE      = '\033[35m'
DARKPURPLE  = '\033[34m'
def banner():
    print(PURPLE+"""
╔═╗┌─┐┬─┐┌┬┐╔═╗┌┐┌┬┌─┐┌─┐
║  ├┤ ├┬┘ │ ╚═╗││││├┤ ├┤ 
╚═╝└─┘┴└─ ┴ ╚═╝┘└┘┴└  └  
Certificate Transparency Log Sniffer"""+GREY+"""
-----------------------------------------------------------------------------------------""")

parser=argparse.ArgumentParser(description='Domain keyword sniffer using certfiicate transparency logs.')
parser.add_argument('-f','--file',help='file containing keywords to sniff (default: monitor.txt).',required=False)
parser.add_argument('-v','--verbose',help='verbose output (All domains passing through).',required=False,action='store_true')
args=vars(parser.parse_args())
banner()
if args['file'] is not None:
    filename=args['file']
    try:
        with open(str(filename), 'r') as f:
            triggerWords=[line.strip() for line in f]
            print(GREY+"Using sniff words from ["+str(filename)+"]"+ENDC)
            print("")
            time.sleep(2)
    except:
        print(WARNING+"Could not read file ["+str(filename)+"]"+ENDC)
        exit()
else:
    try:
        with open('monitor.txt', 'r') as f:
            triggerWords=[line.strip() for line in f]
            print(GREY+"Using sniff words from [monitor.txt]"+ENDC)
            print("")
            time.sleep(2)
    except Exception as error:
        print(WARNING+"Could not open sniff word file ("+str(error)+")"+ENDC)
        exit()

def print_callback(message, context):
    if message['message_type']=="heartbeat":
        return
    if message['message_type']=="certificate_update":
        all_domains=message['data']['leaf_cert']['all_domains']
        if len(all_domains)==0:
            domain="NULL"
        else:
            domain=all_domains[0]
            if args['verbose'] is True:
                print(BOLD+PURPLE+"["+ENDC+GREY+str(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')+BOLD+PURPLE+"]"+DARKPURPLE+":"+PURPLE+"["+ENDC+GREY+(domain[2:] if domain.startswith('*') else domain)+BOLD+PURPLE+"]"))
            if any(trigger in domain for trigger in triggerWords):
                print(BOLD+PURPLE+"["+ENDC+GREY+str(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')+BOLD+PURPLE+"]"+DARKPURPLE+":"+PURPLE+"["+ENDC+GREY+(domain[2:] if domain.startswith('*') else domain)+BOLD+PURPLE+"]"))
                with open('log.txt', 'a') as f:
                    f.write(str(domain[2:] if domain.startswith('*') else domain)+"\n")
        sys.stdout.flush()

certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
