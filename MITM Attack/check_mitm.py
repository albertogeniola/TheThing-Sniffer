import os
import json
import xml.etree.ElementTree as ET
from colorama import init, Fore, Back, Style
from lxml.etree import XMLParser

PATH="Y:\\OutputReports\\mitm_attack"

if __name__ == '__main__':
    dirs = os.listdir(PATH)
    count = 0
    
    init(autoreset=True)
    
    # Print heading line
    print("experiment_id;Outcome;AttackMethod;TrapUrl;RequestHeaders;RequestContents;Elevated")
    
    with open("mitm_res.csv", "wt") as f:
        f.write("Experiment Id;Outcome;AttackMethod;TrapUrl;RequestHeaders;RequestContents;Elevated\n")
        for d in dirs:  
            mitm_file = os.path.join(PATH,d,"mitm.xml")
            parser = XMLParser(ns_clean=True, recover = True)
            xml = ET.parse(mitm_file,parser)
            
            # Retrieve info about the MITM Attack
            mitm = xml.findall(".//MitmAttack")[0]
            success = mitm.find("Success").text
            pid = mitm.find("ProcessId").text
            elevated = mitm.find("ProcessElevated").text
            proc_image_path = mitm.find("ProcessPath").text
            attack_url = None
            req_headers=None
            req_contents=None
            attack_type = None
            
            request = mitm.find("NetworkInfo/Flow/Request")
            # Sometimes we get missing network info. For now just skip that info
            if request is not None:
                attack_url = request.find("PrettyUrl").text
                
                # Build headers
                headers = dict()
                for h in request.findall(".//Header"):
                    key = h.find("Key").text
                    val = h.find("Value").text
                    headers[key] = val          
                
                req_headers = ''.join("%s=%s," % (k,v) for k,v in headers.iteritems()).strip(",")
                    

            # If the attack was driven by MSI, we will find a new app installed in the control panel.
            apps = xml.findall(".//NewApplications/Application")
            if apps is not None:
                for a in apps:
                    if a.text == "MITM MSI Attack":
                        attack_type = "MSI"
            
            # Otherwise we assume it was an exe
            if attack_type is None:
                attack_type = "EXE"
            
            
            color = ""
            if attack_type == "EXE":
                color = Fore.GREEN + Style.BRIGHT
            elif attack_type == "MSI":
                color = Fore.YELLOW +Style.BRIGHT
            
            if success == "True":
                line = "%s;%s;%s;%s;%s;%s;%s" % (d, success, attack_type, attack_url, req_headers, req_contents, elevated)
                print(color + line)
                f.write(line+"\n")
                count += 1