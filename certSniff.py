import logging
import sys
import datetime
import certstream
import argparse
import time

print("""
                              █████     █████████              ███     ██████     ██████ 
                             ░░███     ███░░░░░███            ░░░     ███░░███   ███░░███
  ██████   ██████  ████████  ███████  ░███    ░░░  ████████   ████   ░███ ░░░   ░███ ░░░ 
 ███░░███ ███░░███░░███░░███░░░███░   ░░█████████ ░░███░░███ ░░███  ███████    ███████   
░███ ░░░ ░███████  ░███ ░░░   ░███     ░░░░░░░░███ ░███ ░███  ░███ ░░░███░    ░░░███░    
░███  ███░███░░░   ░███       ░███ ███ ███    ░███ ░███ ░███  ░███   ░███       ░███     
░░██████ ░░██████  █████      ░░█████ ░░█████████  ████ █████ █████  █████      █████    
 ░░░░░░   ░░░░░░  ░░░░░        ░░░░░   ░░░░░░░░░  ░░░░ ░░░░░ ░░░░░  ░░░░░      ░░░░░     
Certificate Transparency Log Sniffer
-----------------------------------------------------------------------------------------
    """)

parser=argparse.ArgumentParser(description='Domain keyword sniffer using certfiicate transparency logs.')
parser.add_argument('-f','--file',help='file containing keywords to sniff (default: monitor.txt).',required=False)
parser.add_argument('-v','--verbose',help='verbose output (All domains passing through).',required=False,action='store_true')
args=vars(parser.parse_args())

if args['file'] is not None:
    filename=args['file']
    try:
        with open(str(filename), 'r') as f:
            triggerWords=[line.strip() for line in f]
            print("Using sniff words from ["+str(filename)+"]")
            print("")
            time.sleep(2)
    except:
        print("Could not read file ["+str(filename)+"]")
        exit()
else:
    try:
        with open('monitor.txt', 'r') as f:
            triggerWords=[line.strip() for line in f]
            print("Using sniff words from [monitor.txt]")
            print("")
            time.sleep(2)
    except Exception as error:
        print("Could not open sniff word file ("+str(error)+")")
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
                print(str(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')+" - "+domain)) 
            if any(trigger in domain for trigger in triggerWords):
                print(str(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')+" + "+domain))
                with open('log.txt', 'a') as f:
                    f.write(str(datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')+" - "+domain)+"\n")
        sys.stdout.flush()

certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
