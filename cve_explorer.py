import requests
import argparse
import json
import sys
import os
from threading import Thread
from multiprocessing.dummy import Pool as Threads
from dotenv import load_dotenv

# ANSI color codes for console output
BRed = "\033[1;31m"         # Red
BGreen = "\033[1;32m"       # Green
BYellow = "\033[1;33m"      # Yellow
BBlue = "\033[1;34m"        # Blue
Reset = "\033[0m"           # Normal Colour
BPurple = "\033[1;35m"      # Purple

def banner():
    """
    Display the program banner.
    """
    print(f"""{BRed}
   _______      ________            _                     
  / ____\ \    / /  ____|          | |                    
 | |     \ \  / /| |__  __  ___ __ | | ___  _ __ ___ _ __ 
 | |      \ \/ / |  __| \ \/ / '_ \| |/ _ \| '__/ _ \ '__|
 | |____   \  /  | |____ >  <| |_) | | (_) | | |  __/ |   
  \_____|   \/   |______/_/\_\ .__/|_|\___/|_|  \___|_|   
                             | |                       version 1.0 
                             |_|                          
    {Reset}""")

def main():
    """
    Main function to parse command-line arguments and initiate asset discovery.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help="Pass the file containing the list of domains.")
    parser.add_argument('-d', '--domain', help="Enter the domain name.")
    args = parser.parse_args()
    
    file = args.file
    host = args.domain

    if not host and not file:
        print(f"{BRed}\n[X] Oops!! None of any argument passed.\n{Reset}")
        parser.print_help()
        sys.exit(0)

    print(f"\n{BBlue}Fetching the assets of given domain from Shodan......{Reset}\n")

    if file:
        domainList = host_from_file(file)

        scannerThread = Threads(10)
        scannerThread.map(assets_finding, domainList)
        scannerThread.close()
        scannerThread.join()

    if host:
        scannerThread = Thread(target=assets_finding, args=(host, ))
        scannerThread.start()
        scannerThread.join()

    print(f"{BGreen}Each report is generated to a corresponding separate CSV file, Please check the Output Directory.\n{Reset}")

# Reading API Key from .env file
load_dotenv()
apiKey = os.getenv('API_Key')

def host_from_file(domainList):
    """
    Read host from the provided list.
    """
    with open(file=domainList, mode='r') as hostFile:
        assets = hostFile.read()
        hostList = assets.split("\n")
        return hostList

def output_writing_to_csv(data, hostName, IP):
    """
    Write result to a CSV file.
    """
    host = hostName.split(".")[0]
    with open(f'Output/{host}-IP_{IP}.csv', mode='w') as f:
        for cve, summary in data.items():
            f.write(f'\n{cve}: {summary}\n')

def assets_finding(domain):
    """
    Look for the IPs and assigned CVEs.
    """
    CN_count = 0
    CVE_count = 0
    outputDict = dict()

    requestURL = f'https://api.shodan.io/shodan/host/search?key={apiKey}&query=ssl.cert.subject.CN:{domain} 200'
    response = requests.get(requestURL).text
    jsonData = json.loads(response)

    try:
        if jsonData['matches']:
            for value in jsonData['matches']:
                CN_Check = value["ssl"]["cert"]['subject']['CN'].split('.')[-2:]
                CN_Host = ".".join(CN_Check)

                if CN_Host == domain:
                    CN_count += 1
                    assetsIP = value['ip_str']

                    if 'vulns' in value:
                        CVE_count += 1
                        print(f'{BYellow}Got CVE Assigned for the IP:{assetsIP} of {Reset}{domain}\n')

                        for item, data in value['vulns'].items():
                            outputDict[item] = data['summary']

                        if 'Output' in os.listdir(os.getcwd()):
                            output_writing_to_csv(outputDict, domain, assetsIP)
                        else:
                            path = os.path.join(os.getcwd(), 'Output')
                            os.mkdir(path)
                            output_writing_to_csv(outputDict, domain, assetsIP)

                    else:
                        pass
                else:
                    pass

            if CN_count == 0:
                print(f"{BPurple}[X] Oops!! None of any IPs belongs to{Reset} {domain}\n")

            else:
                if CVE_count == 0:
                    print(f"{BGreen}[X] No CVE assigned to any IPs of{Reset} {domain}\n")

        else:
            print(f'{BRed}[X] Oops!! No result found for{Reset} {domain}\n')
    except KeyError:
        pass

if __name__ == '__main__':
    banner()

    try:
        main()
    except KeyboardInterrupt:
        print(f'{BRed}Keyboard Interrupted{Reset}')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
