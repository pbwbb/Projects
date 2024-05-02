# hehe
import sys
import requests
import argparse
import json


with open('API_keys.txt', 'r') as f:
    lines = f.readlines()
    for line in lines:
        if line.startswith("VirusTotal"):
            VirusTotal_key = line.split('=')[1].strip()
        if line.startswith("AbuseIPdb"):
            AbuseIPdb_key = line.split('=')[1].strip()
        if line.startswith("OTX"):
            otx_key = line.split('=')[1].strip()
        if line.startswith("CriminalIP"):
            CriminalIP_key = line.split('=')[1].strip()

# Change API keys here
# AbuseIPdb_key = ""    
# VirusTotal_key = ""
# otx_key = ""
# CriminalIP_key


def logo():
    ascii = '''
    ooOoOOo OooOOo.                      o                    
       O    O     `O                    O                     
       o    o      O                    o                     
       O    O     .o                    O                     
       o    oOooOO'  .oOo  .oOo  .oOoO' o  .oOo. .oOo. `OoOo. 
       O    o        `Ooo. O     O   o  O  O   o OooO'  o     
       O    O            O o     o   O  o  o   O O      O     
    ooOOoOo o'       `OoO' `OoO' `OoO'o Oo oOoO' `OoO'  o     
                                           O                  
                                           o'  by Pedro Webber                
    '''
    print(ascii)
    linha_separacao()
    # I used this https://manytools.org/hacker-tools/ascii-banner/ to make the logo :)

def linha_separacao():
    print("\n"+("-+" * 10))

def ip_api(IP,args):
    try:
        response = requests.get(f"http://ip-api.com/json/{IP}")
        if args.raw == True:
             print(response.text)
        elif response.status_code == 200:
            data = response.json()
            print("IP location:\n")
            print(f"country: {data['country']}({data['countryCode']})")
            print(f"region: {data['regionName']}({data['region']})")
            print(f"city: {data['city']}")
            print(f"zip: {data['zip']}")
            print(f"coordinates: lat: {data['lat']} lon: {data['lon']}")
            print(f"timezone: {data['timezone']}")
            linha_separacao()
    except requests.exceptions.RequestException as e:
            response = "bad request"

def vt(IP,args,VirusTotal_key):
    try:
        headers = {"x-apikey":  VirusTotal_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{IP}", headers=headers)
        if args.raw == True:
            print(response.text)
        elif response.status_code == 200:    
            data = response.json()
            analisys = data['data']['attributes']['last_analysis_results']
            detected = False
            for vendor in analisys.keys():
                if analisys[vendor]['result'] not in ["clean","unrated"]:
                    detected = True 
            if detected == True:
                print("\nVirusTotal analisys:\n")
                print(f"IP: {data['data']['id']} ")
                print(f"AS Owner: {data['data']['attributes']['as_owner']}")
                print(f"votes: \n\tharmless: {data['data']['attributes']['total_votes']['harmless']}\n\tmalicious: {data['data']['attributes']['total_votes']['malicious']}")
                for vendor in analisys.keys():
                    if analisys[vendor]['result'] not in ["clean","unrated"]:
                        print(f"Vendor: {analisys[vendor]['engine_name']}")
                        print(f"Category: {analisys[vendor]['category']}")
                        print(f"Result: {analisys[vendor]['result']}")
                linha_separacao()
            elif detected == False:
                print("VirusTotal analisys:\n")
                print(f"IP: {data['data']['id']} ")
                print(f"AS Owner: {data['data']['attributes']['as_owner']}")
                print(f"votes: \n\tharmless: {data['data']['attributes']['total_votes']['harmless']}\n\tmalicious: {data['data']['attributes']['total_votes']['malicious']}")
                print("No threats detected")
                linha_separacao()
    except requests.exceptions.RequestException as e:
        response = "bad request"

def abuseIP(IP,args,AbuseIPdb_key):
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': IP,'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json','Key': AbuseIPdb_key}
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        if args.raw == True: 
            print(response.text)
        elif response.status_code == 200:
            data = response.json()
            print("\nAbuseIPdb:\n")
            print(f"IP: {data['data']['ipAddress']}")
            print(f"Domain: {data['data']['domain']}")
            for hostname in data['data']['hostnames']:
                print(f"hostnames: {hostname}")
            print(f"Abuse Confidence Score: {data['data']['abuseConfidenceScore']}")
            print(f"IP public: {data['data']['isPublic']}")
            print(f"IP version: {data['data']['ipVersion']}")
            print(f"Whitelisted: {data['data']['isWhitelisted']}")
            linha_separacao()
    except requests.exceptions.RequestException as e:
        response = "bad request" 

def otx(IP,args,otx_key): 
    try:
        url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{IP}/general'
        headers = {'X-OTX-API-KEY' : otx_key}
        response = requests.request(method='GET', url=url, headers=headers)
        if args.raw == True: 
            print(response.text)
        elif response.status_code == 200:
            data = response.json()
            print("\nOTX AlienVault:\n")
            print(f"IP: {data['indicator']}")
            print(f"Reputation: {data['reputation']}")
            print(f"Pulses: {data['pulse_info']['count']}")
            for pulse in data['pulse_info']['pulses']:
                print(f"Name: {pulse['name']}")
                print("tags:")
                for i in pulse['tags']: print("\t",i)
            if len(data['pulse_info']['related']['alienvault']['malware_families']) > 0:
                print("Malware families(alienvault):")
                for i in data['pulse_info']['related']['alienvault']['malware_families']: print("\t",i)
            if len(data['pulse_info']['related']['other']['malware_families']) > 0:
                print("Malware families(other):")
                for i in data['pulse_info']['related']['other']['malware_families']: print("\t",i)    
            linha_separacao()        
    except requests.exceptions.RequestException as e:
        response = "bad request"

def crimninalip(IP,args,CriminalIP_key):
    try:
        url = (f'https://api.criminalip.io/v1/feature/ip/malicious-info?ip={IP}')
        headers = {'x-api-key': CriminalIP_key}
        response = requests.request(method='GET', url=url, headers=headers)
        if args.raw == True: 
            print(response.text)
        elif response.status_code == 200:
            data = response.json()
            print(f"\nCriminalIP:\n")
            print(f"IP: {data['ip']}")
            print(f"Malicious: {data['is_malicious']}")
            print(f"VPN: {data['is_vpn']}")
            print(f"Remote Access: {data['can_remote_access']}")
            print(f"Open Ports: {data['current_opened_port']['count']}")
            if data['current_opened_port']['count'] > 0:
                for i in data['current_opened_port']['data']:
                    print(f"\tPort: {i['port']} {i['socket_type']}")
                    print(f"\tProtocol: {i['protocol']}\n")
            print(f"Vulnerabilities: {data['vulnerability']['count']} {data['vulnerability']['data']}")
            linha_separacao()
    except requests.exceptions.RequestException as e:
        response = "bad request"

def C2(IP,args):
    try:
        response = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
        data = response.json()
        detected = False
        for c2 in data:
            if IP in c2['ip_address']:
                detected = True
                if args.raw ==True:
                    print(c2)
                else:
                    print(f"\nFEODO C2 tracker by abuse.ch:\n")
                    print(f"IP: {c2['ip_address']}")
                    print(f"Malware: {c2['malware']}")
                    print(f"Port: {c2['port']}")
                    print(f"Status: {c2['status']}")
                    print(f"Hostname: {c2['hostname']}")
                    print(f"Country: {c2['country']}")
                    print(f"Last online: {c2['last_online']}") 
                    linha_separacao()    
        if detected == False:
            print(f"\nFEODO c2 tracker by abuse.ch:\n")
            print(f"Not found on the past 30 days IOCs") 
            linha_separacao()
    except requests.exceptions.RequestException as e:
      response = "bad request"

def main(): 
    description = (f"{logo()}A tool for finding open source information about IP addresses\n All tools used on this script are free, although API keys are necessary for some of them. To get the keys you only need to create an account.\nBe mindiful of API limits\nI am not responsible for any misuse of APIs or tools on this script")
    parser=argparse.ArgumentParser(prog="IPscalper",description=description,epilog="github.com by Pedro Webber")
    parser.add_argument("IP", help="IP address that is going to be searched")
    parser.add_argument("-all", required=False,  action="store_true", help="Uses all tools")
    parser.add_argument("-v","--verbose", required=False,  action="store_true", help="Verbose output")
    parser.add_argument("-geo","--location", required=False,  action="store_true", help="Uses IP-api to get IP location (no key needed)") #IP-API no key
    parser.add_argument("-raw", required=False, action="store_true", help="Displays raw json output")
    parser.add_argument("-vt","--VirusTotal", required=False,  action="store_true", help="Uses VirusTotal api for info (key required -> edit API_keys.txt file or uncomment lines)")
    parser.add_argument("-abuse","--AbuseIPdb", required=False,  action="store_true", help="Uses AbuseIPdb api for info (key required -> edit API_keys.txt file or uncomment lines)")  
    parser.add_argument("-otx","--AlienVault", required=False,  action="store_true", help="Uses OTX AlienVault api for info (key required -> edit API_keys.txt file or uncomment lines)") # alienvault
    parser.add_argument("-showkeys", required=False,  action="store_true", help="display API keys") # display API keys
    parser.add_argument("-criminalip", required=False,  action="store_true", help="Uses CriminalIP api for info (key required -> edit API_keys.txt file or uncomment lines)")
    parser.add_argument("-c2","--Feodo", required=False,  action="store_true", help="Checks if IP is in Abuse.ch Feodo tracker last 30 days C2 IoCs (no key needed)") #https://feodotracker.abuse.ch
    args=parser.parse_args()
    IP = args.IP
    if args.all == True:
        logo()
        ip_api(IP,args)
        abuseIP(IP,args,AbuseIPdb_key)
        crimninalip(IP,args,CriminalIP_key)
        vt(IP,args,VirusTotal_key)
        otx(IP,args,otx_key) 
        C2(IP,args)       
    else:
        logo()
        if args.showkeys == True:
            print("API keys:\n")
            print("VirusTotal: ", VirusTotal_key)
            print("AbuseIPdb: ", AbuseIPdb_key)
            print("OTX AlienVault: ", otx_key)
            print("CriminalIP: ", CriminalIP_key)
        if args.geo == True:
            ip_api(IP,args)
        if args.abuse == True:
            abuseIP(IP,args,AbuseIPdb_key)
        if args.criminalip ==  True:
            crimninalip(IP,args,CriminalIP_key)
        if args.vt == True:
            vt(IP,args,VirusTotal_key)
        if args.otx == True:
            otx(IP,args,otx_key)
        if args.c2 == True:
            C2(IP,args)
   
if __name__ == "__main__":
    main()



