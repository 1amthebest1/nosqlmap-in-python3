from exception import NoSQLMapException
import sys
import nsmcouch
import nsmmongo
import nsmscan
import nsmweb
import os
import signal
import ast
import argparse

def main(args):
    signal.signal(signal.SIGINT, signal_handler)
    global optionSet
    optionSet = [False]*9
    global yes_tag
    global no_tag
    yes_tag = ['y', 'Y']
    no_tag = ['n', 'N']
    global victim
    global webPort
    global uri
    global httpMethod
    global platform
    global https
    global myIP
    global myPort
    global verb
    global scanNeedCreds
    global dbPort
    
    platform = "MongoDB"
    dbPort = 27017
    myIP = "Not Set"
    myPort = "Not Set"
    
    if args.attack:
        attack(args)
    else:
        mainMenu()

def mainMenu():
    global platform
    global victim
    global dbPort
    global myIP
    global webPort
    global uri
    global httpMethod
    global https
    global verb
    global requestHeaders
    global postData
    
    mmSelect = True
    
    while mmSelect:
        os.system('clear')
        print(" _ _ ___ ___ _ __ __ ")
        print("| \| |___/ __|/ _ \| | | \/ |__ _ _ __ ")
        print("| . / _ \__ \ (_) | |__| |\/| / _ \| '_ \\")
        print("|_|\_\___/___/\__\_\____|_| |_\__,_| .__/")
        print(" v0.7 codingo@protonmail.com |_| ")
        print("\n")
        print("1-Set options")
        print("2-NoSQL DB Access Attacks")
        print("3-NoSQL Web App attacks")
        print("4-Scan for Anonymous " + platform + " Access")
        print("5-Change Platform (Current: " + platform + ")")
        print("x-Exit")
        
        select = input("Select an option: ")
        
        if select == "1":
            options()
        elif select == "2":
            if optionSet[0] == True and optionSet[4] == True:
                if platform == "MongoDB":
                    nsmmongo.netAttacks(victim, dbPort, myIP, myPort)
                elif platform == "CouchDB":
                    nsmcouch.netAttacks(victim, dbPort, myIP)
            else:
                input("Target not set! Check options. Press enter to continue...")
        elif select == "3":
            if optionSet[0] == True and optionSet[2] == True:
                if httpMethod == "GET":
                    nsmweb.getApps(webPort, victim, uri, https, verb, requestHeaders)
                elif httpMethod == "POST":
                    nsmweb.postApps(victim, webPort, uri, https, verb, postData, requestHeaders)
            else:
                input("Options not set! Check host and URI path. Press enter to continue...")
        elif select == "4":
            scanResult = nsmscan.massScan(platform)
            if scanResult is not None:
                optionSet[0] = True
                victim = scanResult[1]
        elif select == "5":
            platSel()
        elif select == "x":
            sys.exit()
        else:
            input("Invalid selection. Press enter to continue...")

def build_request_headers(reqHeadersIn):
    requestHeaders = {}
    reqHeadersArray = reqHeadersIn.split(",")
    headerNames = reqHeadersArray[0::2]
    headerValues = reqHeadersArray[1::2]
    requestHeaders = dict(zip(headerNames, headerValues))
    return requestHeaders

def build_post_data(postDataIn):
    pdArray = postDataIn.split(",")
    paramNames = pdArray[0::2]
    paramValues = pdArray[1::2]
    postData = dict(zip(paramNames,paramValues))
    return postData

def attack(args):
    platform = args.platform
    victim = args.victim
    webPort = args.webPort
    dbPort = args.dbPort
    myIP = args.myIP
    myPort = args.myPort
    uri = args.uri
    https = args.https
    verb = args.verb
    httpMethod = args.httpMethod
    requestHeaders = build_request_headers(args.requestHeaders)
    postData = build_post_data(args.postData)
    
    if args.attack == 1:
        if platform == "MongoDB":
            nsmmongo.netAttacks(victim, dbPort, myIP, myPort, args)
        elif platform == "CouchDB":
            nsmcouch.netAttacks(victim, dbPort, myIP, args)
    elif args.attack == 2:
        if httpMethod == "GET":
            nsmweb.getApps(webPort, victim, uri, https, verb, requestHeaders, args)
        elif httpMethod == "POST":
            nsmweb.postApps(victim, webPort, uri, https, verb, postData, requestHeaders, args)
    elif args.attack == 3:
        scanResult = nsmscan.massScan(platform)
        if scanResult is not None:
            optionSet[0] = True
            victim = scanResult[1]

def platSel():
    global platform
    global dbPort
    
    select = True
    print("\n")
    
    while select:
        print("1-MongoDB")
        print("2-CouchDB")
        
        pSel = input("Select a platform: ")
        
        if pSel == "1":
            platform = "MongoDB"
            dbPort = 27017
            return
        elif pSel == "2":
            platform = "CouchDB"
            dbPort = 5984
            return
        else:
            input("Invalid selection. Press enter to continue...")

def options():
    global victim
    global webPort
    global uri
    global https
    global platform
    global httpMethod
    global postData
    global myIP
    global myPort
    global verb
    global mmSelect
    global dbPort
    global requestHeaders
    
    requestHeaders = {}
    optSelect = True
    
    if optionSet[0] == False:
        global victim
        victim = "Not Set"
    if optionSet[1] == False:
        global webPort
        webPort = 80
        optionSet[1] = True
    if optionSet[2] == False:
        global uri
        uri = "Not Set"
    if optionSet[3] == False:
        global httpMethod
        httpMethod = "GET"
    if optionSet[4] == False:
        global myIP
        myIP = "Not Set"
    if optionSet[5] == False:
        global myPort
        myPort = "Not Set"
    if optionSet[6] == False:
        verb = "OFF"
        optSelect = True
    if optionSet[8] == False:
        https = "OFF"
        optSelect = True
    
    while optSelect:
        print("\n\n")
        print("Options")
        print("1-Set target host/IP (Current: " + str(victim) + ")")
        print("2-Set web app port (Current: " + str(webPort) + ")")
        print("3-Set App Path (Current: " + str(uri) + ")")
        print("4-Toggle HTTPS (Current: " + str(https) + ")")
        print("5-Set " + platform + " Port (Current : " + str(dbPort) + ")")
        print("6-Set HTTP Request Method (GET/POST) (Current: " + httpMethod + ")")
        print("7-Set my local " + platform + "/Shell IP (Current: " + str(myIP) + ")")
        print("8-Set shell listener port (Current: " + str(myPort) + ")")
        print("9-Toggle Verbose Mode: (Current: " + str(verb) + ")")
        print("0-Load options file")
        print("a-Load options from saved Burp request")
        print("b-Save options file")
        print("h-Set headers")
        print("x-Back to main menu")
        
        select = input("Select an option: ")
        
        if select == "1":
            optionSet[0] = False
            ipLen = False
            
            while optionSet[0] == False:
                goodDigits = True
                notDNS = True
                victim = input("Enter the host IP/DNS name: ")
                
                octets = victim.split(".")
                
                if len(octets) != 4:
                    optionSet[0] = True
                    notDNS = False
                else:
                    for item in octets:
                        try:
                            if int(item) < 0 or int(item) > 255:
                                print("Bad octet in IP address.")
                                goodDigits = False
                        except ValueError:
                            raise NoSQLMapException("[!] Must be a DNS name.")
                            notDNS = False
                            
                if goodDigits == True or notDNS == False:
                    print("\nTarget set to " + victim + "\n")
                    optionSet[0] = True
        
        elif select == "2":
            webPort = input("Enter the HTTP port for web apps: ")
            print("\nHTTP port set to " + webPort + "\n")
            optionSet[1] = True
        elif select == "3":
            uri = input("Enter the URI of the application: ")
            print("\nURI set to " + uri + "\n")
            optionSet[2] = True
        elif select == "4":
            if https == "OFF":
                https = "ON"
                print("\nHTTPS turned ON\n")
            elif https == "ON":
                https = "OFF"
                print("\nHTTPS turned OFF\n")
        elif select == "5":
            dbPort = input("Enter the " + platform + " Port number: ")
            print("\n" + platform + " port set to " + dbPort + "\n")
        elif select == "6":
            if httpMethod == "GET":
                httpMethod = "POST"
                print("\nHTTP Method set to POST\n")
            elif httpMethod == "POST":
                httpMethod = "GET"
                print("\nHTTP Method set to GET\n")
        elif select == "7":
            myIP = input("Enter your local IP: ")
            print("\nYour IP set to " + myIP + "\n")
            optionSet[5] = True
        elif select == "8":
            myPort = input("Enter the port to listen on: ")
            print("\nLocal port set to " + myPort + "\n")
            optionSet[6] = True
        elif select == "9":
            if verb == "OFF":
                verb = "ON"
                print("\nVerbose mode ON\n")
            elif verb == "ON":
                verb = "OFF"
                print("\nVerbose mode OFF\n")
        elif select == "0":
            print("\n")
            load_options()
        elif select == "a":
            print("\n")
            load_options_burp()
        elif select == "b":
            print("\n")
            save_options()
        elif select == "h":
            set_headers()
        elif select == "x":
            optSelect = False

def load_options():
    pass

def load_options_burp():
    pass

def save_options():
    pass

def set_headers():
    global requestHeaders
    global optSelect
    global myIP
    global myPort
    global verb
    global https
    
    optSelect = True
    
    print("\n\n")
    print("Options")
    print("1-Set target host/IP (Current: " + str(victim) + ")")
    print("2-Set web app port (Current: " + str(webPort) + ")")
    print("3-Set App Path (Current: " + str(uri) + ")")
    print("4-Toggle HTTPS (Current: " + str(https) + ")")
    print("5-Set " + platform + " Port (Current : " + str(dbPort) + ")")
    print("6-Set HTTP Request Method (GET/POST) (Current: " + httpMethod + ")")
    print("7-Set my local " + platform + "/Shell IP (Current: " + str(myIP) + ")")
    print("8-Set shell listener port (Current: " + str(myPort) + ")")
    print("9-Toggle Verbose Mode: (Current: " + str(verb) + ")")
    print("0-Load options file")
    print("a-Load options from saved Burp request")
    print("b-Save options file")
    print("h-Set headers")
    print("x-Back to main menu")
    
    select = input("Select an option: ")
    
    if select == "1":
        optionSet[0] = False
        ipLen = False
        
        while optionSet[0] == False:
            goodDigits = True
            notDNS = True
            victim = input("Enter the host IP/DNS name: ")
            
            octets = victim.split(".")
            
            if len(octets) != 4:
                optionSet[0] = True
                notDNS = False
            else:
                for item in octets:
                    try:
                        if int(item) < 0 or int(item) > 255:
                            print("Bad octet in IP address.")
                            goodDigits = False
                    except ValueError:
                        raise NoSQLMapException("[!] Must be a DNS name.")
                        notDNS = False
                        
            if goodDigits == True or notDNS == False:
                print("\nTarget set to " + victim + "\n")
                optionSet[0] = True
    
    elif select == "2":
        webPort = input("Enter the HTTP port for web apps: ")
        print("\nHTTP port set to " + webPort + "\n")
        optionSet[1] = True
    elif select == "3":
        uri = input("Enter the URI of the application: ")
        print("\nURI set to " + uri + "\n")
        optionSet[2] = True
    elif select == "4":
        if https == "OFF":
            https = "ON"
            print("\nHTTPS turned ON\n")
        elif https == "ON":
            https = "OFF"
            print("\nHTTPS turned OFF\n")
    elif select == "5":
        dbPort = input("Enter the " + platform + " Port number: ")
        print("\n" + platform + " port set to " + dbPort + "\n")
    elif select == "6":
        if httpMethod == "GET":
            httpMethod = "POST"
            print("\nHTTP Method set to POST\n")
        elif httpMethod == "POST":
            httpMethod = "GET"
            print("\nHTTP Method set to GET\n")
    elif select == "7":
        myIP = input("Enter your local IP: ")
        print("\nYour IP set to " + myIP + "\n")
        optionSet[5] = True
    elif select == "8":
        myPort = input("Enter the port to listen on: ")
        print("\nLocal port set to " + myPort + "\n")
        optionSet[6] = True
    elif select == "9":
        if verb == "OFF":
            verb = "ON"
            print("\nVerbose mode ON\n")
        elif verb == "ON":
            verb = "OFF"
            print("\nVerbose mode OFF\n")
    elif select == "0":
        print("\n")
        load_options()
    elif select == "a":
        print("\n")
        load_options_burp()
    elif select == "b":
        print("\n")
        save_options()
    elif select == "h":
        set_headers()
    elif select == "x":
        optSelect = False

def signal_handler(signal, frame):
    print("\nCtrl+C caught. Exiting...")
    sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NoSQLMap - Automated MongoDB and CouchDB Database Enumeration and Web Application Exploitation")
    parser.add_argument("-a", "--attack", type=int, choices=[1, 2, 3], help="1: Database Attacks, 2: Web Attacks, 3: Scan for Anonymous Access", required=False)
    parser.add_argument("-p", "--platform", type=str, choices=["MongoDB", "CouchDB"], help="Specify the platform (MongoDB or CouchDB)", required=False)
    parser.add_argument("-v", "--victim", type=str, help="Specify the victim IP address or domain name", required=False)
    parser.add_argument("-w", "--webPort", type=int, help="Specify the web app port", required=False)
    parser.add_argument("-d", "--dbPort", type=int, help="Specify the database port", required=False)
    parser.add_argument("-i", "--myIP", type=str, help="Specify your IP address", required=False)
    parser.add_argument("-l", "--myPort", type=int, help="Specify your listening port", required=False)
    parser.add_argument("-u", "--uri", type=str, help="Specify the URI of the web application", required=False)
    parser.add_argument("-s", "--https", action="store_true", help="Toggle HTTPS on", required=False)
    parser.add_argument("-m", "--httpMethod", type=str, choices=["GET", "POST"], help="Specify HTTP request method (GET or POST)", required=False)
    parser.add_argument("-b", "--requestHeaders", type=str, help="Specify HTTP request headers", required=False)
    parser.add_argument("-o", "--postData", type=str, help="Specify POST data", required=False)
    parser.add_argument("-e", "--verb", action="store_true", help="Toggle verbose mode on", required=False)
    args = parser.parse_args()
    main(args)

