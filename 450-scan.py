import time
from urllib import request
from hashlib import *
from socket import *
from urllib.parse import urlsplit
import urllib.parse as urlparse
from urllib.parse import parse_qs   
import os
import webtech
import whois


try:
    from bs4 import BeautifulSoup
except:
    os.system("clear")
    print(colored("\nbs4 library need to be installed. Use:\npip3 install bs4", "red"))
    exit()


try:
    from termcolor import colored
except:
    os.system("clear")
    print(colored("\ntermcolor library need to be installed. Use:\npip3 install termcolor", "red"))
    exit()


try:
    import requests
except:
    os.system("clear")
    print(colored("\nrequests library need to be installed. Use:\npip3 install requests", "red"))
    exit()

try:
    import webtech
except:
    os.system("clear")
    print(colored("\nwebtech library need to be installed. Use:\npip3 install webtech", "red"))
    exit()


try:
    import argparse
except:
    os.system("clear")
    print(colored("\nargparse library need to be installed. Use:\npip3 install argparse", "red"))
    exit()


def logo():
    print("""
\x1b[34m
    
           4  55555  000         SSSS  CCC    A   N   N 
          44  5     0   0       S     C   C  A A  NN  N 
         4 4  5555  0 0 0        SSS  C     AAAAA N N N 
        4444      5 0   0           S C   C A   A N  NN 
           4  5555   000  _____ SSSS   CCC  A   A N   N 
  ------------------------------------------------------------------
                    Version     : Under Development
                    Institute   : SUST CSE
                    Author      : Navid & Mustaqur
                    Project For : Project 450
 ------------------------------------------------------------------
                                                                                                               
""")


def fast_crawl(url):
    global list_direct, url_access, url_source
    ip = url.strip("https://www.")
    print("Domain:",url)
    print("IP:",gethostbyname(ip))
    list_direct = []
    url_strip = url.strip("https://www.")
    headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0"}
    list_direct.append(url)
    url_request = requests.get(url, headers=headers)
    url_source = BeautifulSoup(url_request.content, "html.parser")
    for link in url_source.find_all("a"):
        link_pure = link.get("href")
        try:
            if "#" in link_pure or "../" in link_pure or "facebook.com" in link_pure or "@" in link_pure:
                pass
            else:
                if "http" not in link_pure and "https" not in link_pure and url_strip not in link_pure:
                    try:
                        first_req = requests.get(url + link_pure)
                        if first_req.status_code == 200:
                            print(colored("================================================================", "green"))
                            print(colored("Url:", "green"), url + link_pure)
                            print(colored("Request:", "green"), first_req.status_code)
                            print(colored("================================================================", "green"))
                            list_direct.append(url + link_pure)
                        else:
                            pass
                    except requests.exceptions.ConnectionError:
                        pass
                else:
                    if "http" in link_pure or "https" in link_pure and url_strip in link_pure:
                        try:
                            sec_req = requests.get(link_pure)
                            if sec_req.status_code == 200:
                                if sec_req.url not in list_direct:
                                    print(colored("================================================================",
                                                  "green"))
                                    print(colored("Url:", "green"), link_pure)
                                    print(colored("Request:", "green"), sec_req.status_code)
                                    print(colored("================================================================",
                                                  "green"))
                                    list_direct.append(link_pure)
                            else:
                                pass
                        except requests.exceptions.ConnectionError:
                            pass
                    elif "http" not in link_pure or "https" not in link_pure and url_strip in link_pure:
                        try:
                            third_req = requests.get("http://" + link_pure)
                            if third_req.status_code == 200:
                                if third_req.url not in list_direct:
                                    print(colored("================================================================",
                                                  "green"))
                                    print(colored("Url:", "green"), third_req.url)
                                    print(colored("Request:", "green"), third_req.status_code)
                                    print(colored("================================================================",
                                                  "green"))
                                    list_direct.append("http://" + link_pure)
                            else:
                                pass
                        except requests.exceptions.ConnectionError:
                            pass
                    else:
                        try:
                            fourth_req = requests.get(link_pure)
                            if fourth_req.status_code == 200:
                                if fourth_req.url not in list_direct:
                                    print(colored("================================================================",
                                                  "green"))
                                    print(colored("Url:", "green"), fourth_req.url)
                                    print(colored("Request:", "green"), fourth_req.status_code)
                                    print(colored("================================================================",
                                                  "green"))
                                    list_direct.append(fourth_req.url)
                            else:
                                pass
                        except requests.exceptions.ConnectionError:
                            pass
        except:
            pass
    for url_form_list in list_direct:
        sec_url_request = requests.get(url_form_list)
        soup = BeautifulSoup(sec_url_request.content, "html.parser")
        for sec_link in soup.find_all("a"):
            sec_link = sec_link.get("href")
            try:
                if "#" in sec_link or "./" in sec_link:
                    pass
                else:
                    if url_strip not in sec_link:
                        pass
                    else:
                        if "http" not in sec_link or "https" not in sec_link and url_strip in sec_link:
                            try:
                                five_req = requests.get("http://" + sec_link)
                                if five_req.status_code == 200:
                                    if five_req.url not in list_direct:
                                        print(
                                            colored("================================================================",
                                                    "green"))
                                        print(colored("Url:", "green"), five_req.url)
                                        print(colored("Request:", "green"), five_req.status_code)
                                        print(
                                            colored("================================================================",
                                                    "green"))
                                        list_direct.append(five_req.url)
                                else:
                                    pass
                            except:
                                pass
                        else:
                            try:
                                six_req = requests.get(sec_link)
                                if six_req.status_code == 200:
                                    if six_req.url not in list_direct:
                                        print(
                                            colored("================================================================",
                                                    "green"))
                                        print(colored("Url:", "green"), six_req.url)
                                        print(colored("Request:", "green"), six_req.status_code)
                                        print(
                                            colored("================================================================",
                                                    "green"))
                                        list_direct.append(six_req.url)
                                else:
                                    pass
                            except:
                                pass
            except:
                pass

# main part start form here

# port scanning
def scanports(url):
    if __name__ == "__main__":
        target = url
        t_IP = gethostbyname(target)
        print('Starting scan on host: ', t_IP)
        common_ports = [80,23,443,21,22,113,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427]
    for i in common_ports:
        s = socket(AF_INET, SOCK_STREAM)

        conn = s.connect_ex((t_IP, i))
        if (conn == 0):
            print('Port %d: OPEN' % (i,))
        s.close()

# Finding Probable Admin Login Pages

def admin_directory(url):
    file_format = open("link.txt", "r")
    try:
        for link in file_format:
            Purl = url + "/" + link
            if Purl == None:
                exit()
            req_link = requests.get(Purl)
            if req_link.status_code == 200:
                print(colored("[+]Found: ", "green"), Purl)
            else:
                print(colored("[-]Not Found: ", "red"), Purl)
    except requests.exceptions.ConnectionError:
        pass


# Detecting used technology stack
wt = webtech.WebTech()

def usedWebTech(url):
    try:
        results = wt.start_from_url(url, timeout=2)
        print(colored(results, "green"))
    except requests.exceptions.ConnectionError:
        pass

# Whois Lookup
def whois_lookup(url):
    import whois
    w = whois.whois(url)
    print(w)

# intermediate code. Is this site live or not
def httplive(url):
    global live
    live = None
    bool(live)
    try:
        request_live = requests.get(url)
        if request_live.status_code == 200:
            print(colored("Http Live : ", "green"), url)
            live = 1
    except requests.exceptions.ConnectionError:
        print(colored("Http Down : ", "red"), url)
        live = 0

# find different types of directory
def spider(url, lists, secure):
    print(colored("Please Wait We Check if URL Live or Down . . ", "green"))
    time.sleep(3)
    httplive(url)
    if live == 1:
        if secure == "list.txt":
            print(colored("Please Wait We Spider all Directories . .", "red"))
            time.sleep(3)
            fast_crawl(url)
            print(colored("We Crawling By This File >>" + os.getcwd() + "/" + "list.txt", "green"))
            for i in lists:
                i = i.strip()
                Purl = url + "/" + i
                response = requests.get(Purl)
                if response.status_code == 200:
                    print("\x1b[32mFound[+]")
                    print(response.url)
                else:
                    pass
        else:
            fast_crawl(url)
            print(colored("We Crawling By This File >>" + listuser, "green"))
            for i in lists:
                i = i.strip()
                Purl = url + "/" + i
                response = requests.get(Purl)
                if response.status_code == 200:
                    print("\x1b[32mFound[+]")
                    print(response.url)
                else:
                    pass
    else:
        pass

def sql(url):  # Function F0r find Sql_Injection

    try:
        parametrs = []
        after_eq = []
        get = {}
        query = urlsplit(url).query
        dictonary = parse_qs(query)
        key = list(dictonary.keys())
        value = list(dictonary.values())
        for par in key:
            parametrs.append(par)
        for equal in value:
            for number in equal:
                after_eq.append(number + "'")
        for pars in parametrs:
            for eq in after_eq:
                get = {pars: eq}
        get_list = list(get)
        for item in get_list:
            item = item.strip()
            if item != None:
                req = requests.get(url, params=get)
                if "Warning" in req.text or "Database error" in req.text or "MySQL error" in req.text or "SQL syntax" in req.text:
                    print(colored("================================================================", "green"))
                    print(colored("SQL Injection", "red"), colored("Type:Union Based", "grey"))
                    print(colored("Url Vulnerable:", "green"), colored(req.url, "red"))
                    print(colored("================================================================", "green"))
                    url_sql.append(req.url)
                else:
                    print(colored("================================================================", "green"))
                    print(colored("Url Not Vulnerable:", "green"), colored(req.url, "red"))
                    print(colored("================================================================", "green"))
            else:
                pass
    except:
        pass


def xss(url):  # Function FOr Find xss vulnerability
    # GET Method
    try:
        GET = {}
        file = open("xss_payloads.txt", "r")
        parsed = urlparse.urlparse(url)
        params = urlparse.parse_qsl(parsed.query)
        print(colored("Parameters in Link:","red"),colored(params[0],"green"))
        print(colored("Please wait we check if parameters vulnerable ","red"))
        time.sleep(5)
        for payload in file:
            payload = payload.strip()
            for par, equeal in params:
                GET = {par: payload}
                check_req = requests.get(url, params=GET)
                if payload in check_req.text:
                    time.sleep(2)
                    print(colored("=========================================================", "green"))
                    print(colored("Url:", "green"), colored(url, "blue"))
                    print(colored("Method:", "green"), colored("GET", "red"))
                    print(colored("Url Vulnerable", "red"), check_req.url)
                    print(colored("Parameter Vulnerable:", "red"), par)
                    print(colored("Payload:", "red"), payload)
                    print(colored("=========================================================", "green"))
                else:
                    time.sleep(2)
                    print(colored("=========================================================", "green"))
                    print(colored("Url:", "green"), colored(url, "blue"))
                    print(colored("Method:", "green"), colored("GET", "red"))
                    print(colored("Url Not Vulnerable", "green"), check_req.url)
                    print(colored("Parameter Not Vulnerable:", "green"), par)
                    print(colored("Payload:", "red"), payload)
                    print(colored("=========================================================", "green"))
        file.close()
    except:
        pass
    # Post Method
    try:
        POST = {}
        New_open = open("xss_payloads.txt")
        request_form = request.urlopen(url).read()
        source = BeautifulSoup(request_form, "html.parser")
        for payloads in New_open:
            for form in source.findAll("input"):
                if form.get('type') == "submit":
                    input_submit = form.get('name')
                    POST[input_submit] = payloads
                if form.get('type') == 'text':
                    input_name = form.get('name')
                    POST[input_name] = payloads
            sec_check_req = requests.post(url, POST)
            if payloads in sec_check_req.text:
                time.sleep(2)
                print(colored("=========================================================", "green"))
                print(colored("Url:", "green"), colored(url, "blue"))
                print(colored("Method:", "green"), colored("POST", "red"))
                print(colored("Url Vulnerable", "red"), sec_check_req.url)
                print(colored("Parameter Vulnerable:", "red"), input_name)
                print(colored("Payload:", "red"), payloads)
                print(colored("=========================================================", "green"))
            else:
                time.sleep(2)
                print(colored("=========================================================", "green"))
                print(colored("Url:", "green"), colored(url, "blue"))
                print(colored("Method:", "green"), colored("POST", "red"))
                print(colored("Url Not Vulnerable", "green"), sec_check_req.url)
                print(colored("Parameter Not Vulnerable:", "green"), input_name)
                print(colored("=========================================================", "green"))


        New_open.close()
    except:
        pass


def html_injection(url):
    # GET
    try:
        file = open("html_payloads.txt", "r")
        GET = {}
        parsed = urlparse.urlparse(url)
        params = urlparse.parse_qsl(parsed.query)
        for payload in file:
            payload = payload.strip()
            for par,equal in params:
                print(colored(par,"green"),"=",colored(equal,"green"))
                GET={par:payload}
                req = requests.get(url,params=GET)
                if payload in req.text:
                    print(colored("=========================================================", "green"))
                    print(colored("Url:", "green"), colored(url, "blue"))
                    print(colored("Method:", "green"), colored("GET", "red"))
                    print(colored("Url Vulnerable", "red"), req.url)
                    print(colored("Parameter:", "red"), par)
                    print(colored("Payload:", "red"), payload)
                    print(colored("=========================================================", "green"))
        file.close()

    except:
        pass
    #POST
    try:
        POST = {}
        file_payloads = open("html_payloads.txt")
        request_form = request.urlopen(url).read()
        source = BeautifulSoup(request_form, "html.parser")
        for payload in file_payloads:
            for form in source.findAll("input"):
                if form.get('type') == "submit":
                    input_submit = form.get('name')
                    POST[input_submit] = payload
                if form.get('type') == 'text':
                    input_name = form.get('name')
                    POST[input_name] = payload
            req_check = requests.post(url, POST)
            if payload in req_check.text:
                print(colored("=========================================================", "green"))
                print(colored("Url:", "green"), colored(url, "blue"))
                print(colored("Method:", "green"), colored("POST", "red"))
                print(colored("Url Vulnerable", "red"), req_check.url)
                print(colored("Parameter:", "red"), input_name)
                print(colored("Payload:", "red"), payload)
                print(colored("=========================================================", "green"))
        file_payloads.close()
    except:
        pass

def sub(url, subs):  # function for gussing subdomain
    if "https" in url:
        url = url.strip("https://")
    elif "http" in url:
        url = url.strip("http://")
    for i in subs:
        i = i.strip()
        Purl = i + "." + url
        try:
            response = requests.get("http://" + Purl)
            if response.status_code == 200:
                print(colored("=========================================================", "green"))
                print(colored("Url:http://{0}", "green").format(Purl))
                print(colored("Status_Code:","red"),colored(200,"green"))
                print(colored("=========================================================", "green"))
            else:
                pass
        except:
            pass

def update():
    print('Please Update this code from my github repo')


parser = argparse.ArgumentParser("""
    <---:::Web Application Reconnaissance:::--->

--port              : Scan ports by ip
--webtech           : Detecting used technology stack
--spider            : Url to find Directory
--adminPanel        : List available Admin Panel
--domaininfo        : Finding Whois Lookup Table
--subdomain         : find SubDomain of site
--xss               : Scan Site if vulnerable [Xss] url must be between double citation
--sql               : Scan Site if vulnerable [Sql] url must be between double citation
--HTMLinj           : Scan site if vulnerable [html injection] url must be between double citation
--update            : Update Tool ex: --update check

        <-----:::Example:::---->

python3 450-scan.py --port http://testphp.vulnweb.com/
python3 450-scan.py --webtech http://sust.edu
python3 450-scan.py --spider http://sust.edu
python3 450-scan.py --xss http://testphp.vulnweb.com/listproducts.php?cat=1
python3 450-scan.py --domaininfo "paste url here"
python3 450-scan.py --sql "paste url here"
python3 450-scan.py --subdomain google.com

""")
parser.add_argument("-webtech", "--webtech")
parser.add_argument("-spider", "--spider")
parser.add_argument("-adminPanel","--adminPanel")
parser.add_argument("-domaininfo","--domaininfo")
parser.add_argument("-subdomain", "--subdomain")
parser.add_argument("-xss", "--xss")
parser.add_argument("-sql", "--sql")
parser.add_argument("-HTMLinj","--HTMLinj")
parser.add_argument("-update", "--update")
parser.add_argument("-port", "--port")
parser.add_argument("-list","--list")
args = parser.parse_args()
secure = None
listuser = args.list
if listuser != None:
    listuser = args.list
    secure = None
elif listuser == None:
    listuser = open("list.txt", "r")
    secure = "list.txt"
portscan = args.port 
webtech = args.webtech
who_is = args.domaininfo
url = args.spider
admin_dir = args.adminPanel 
subdomains = args.subdomain
scanner = args.xss
sql_inection = args.sql
updates = args.update
html = args.HTMLinj
sublist = open("sub.txt", "r")

    
if sql_inection == None and who_is  == None and scanner == None and url == None and subdomains == None and  updates == None and  portscan != None and webtech == None and html == None  :
    scanports(portscan)

elif sql_inection == None and who_is  == None and scanner == None and url == None and subdomains == None and  updates == None and  portscan == None and webtech != None and html == None  :
    usedWebTech(webtech)

elif url != None and subdomains == None and scanner == None and sql_inection == None and who_is  == None and  updates == None and  portscan == None and webtech==None and html == None  :
    spider(url, listuser, secure)

elif admin_dir != None and subdomains == None and scanner == None and sql_inection == None and who_is  == None and  updates == None and  portscan == None and webtech==None and html == None  :
    admin_directory(admin_dir)

elif subdomains != None and url == None and scanner == None and sql_inection == None and who_is  == None and  updates == None and  portscan == None and webtech==None and html == None  :
    sub(subdomains, sublist)

elif scanner != None and url == None and subdomains == None and sql_inection == None and who_is  == None and  updates == None and  portscan == None and webtech==None and html == None  :
    xss(scanner)

elif sql_inection != None and who_is  == None and scanner == None and url == None and subdomains == None and  updates == None and  portscan == None and webtech==None and html == None  :
    sql(sql_inection)

elif sql_inection == None and who_is  == None and scanner == None and url == None and subdomains == None and  updates != None and  portscan == None and webtech==None and html == None  :
    if updates == "check" or updates == "Check":
        update()
    else:
        print(colored("Error ! Please Enter --update check", "red"))
elif sql_inection == None and who_is != None and scanner == None and url == None and subdomains == None and  updates == None and portscan == None and webtech==None and html == None  :
    whois_lookup(who_is)

elif sql_inection == None and who_is  == None and scanner == None and url == None and subdomains == None and  updates == None and  portscan == None and webtech==None and html != None  :
    html_injection(html)

else:
    logo()

