import requests
from bs4 import BeautifulSoup as bs 
from urllib.parse import urljoin
from lib import errors_db


s = requests.Session()    
s.headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36" 


def get_all_forms(url):
    
    r = requests.get(url)
    soup = bs(r.content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):

    details = {}

    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    
    method = form.attrs.get("method", "get").lower()

    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type":input_type, "name":input_name, "value":input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    return details

def is_vulnerable(response):

    errors = errors_db.error()


    for title,error in errors.items():
        if error in response.content.decode().lower():
            return True,title,error
        
    return False,None,None 

def scan(url):

    value = ("'","/",'"')

    for c in value:
        new_url = url+c
        print("[*]Trying {}".format(new_url))
        
        response = s.get(new_url)
        loop,title,error = is_vulnerable(response)

        if loop:

            print("[!]SQL injection Vulnerability detected, Link:", new_url)
            file = open("vuln.txt","a+")
            file.write("{} = {} : {}\n".format(url,title,error))
            break 
    
    forms = get_all_forms(url)
    print("[+] Detected {} forms on {}.".format(len(forms),url))

    for form in forms:
        form_detail = get_form_details(form)
        
        for c in value:

            data = {}
            for input_tag in form_detail["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass 
                elif input_tag["type"] != "submit":
                    
                    try:
                        data[input_tag["name"]] = "test{}".format(c)
                    except:
                        pass 
            file = open("lib\\random.txt","r")
            a = file.readlines()
            print("[*]Trying....")
            try:
                for i in a: 
                    url = urljoin(url, form_detail["action"])
                    form_detail["action"] = i + c
                    if form_detail["method"] == "post":
                        response = s.post(url, data=data)
                    elif form_detail["method"] == "get":
                        response = s.get(url, params=data)
                    
                    loop,title,error = is_vulnerable(response)
                    if loop:
                        print("[+] SQL Injection vulnerability detected, link:", url)
                        print("[+] Form:")
                        print(form_detail)
                        file = open("vuln.txt","a+")
                        file.write("{} = {} : {}\n".format(url,title,error))
                        file.write(form_detail)
                        break
            except KeyboardInterrupt:
                print("[!]User Canceled Detect...")
                return 

            file.close()
if __name__ == "__main__":
    import argparse
    import sys 

    parser = argparse.ArgumentParser(description='SQL Injection Scanner')
    parser.add_argument('-u' '--url', help='WebSite Url ', action='store', dest='url', default=False)
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    elif not args.url:
        parser.error('Invalid url')
        sys.exit(1)
        

    url = args.url
    scan(url)
    print("[*]DONE! All information saved in vuln.txt file")
