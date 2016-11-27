import re
import sys
import time
import Queue
import urllib
import logging
import tabulate
import requests
import mechanize
import threading
import subprocess
import tldextract
from bs4 import BeautifulSoup
from model import Vulnerabilities
from urlparse import urlparse, parse_qs
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
logging.basicConfig(level=logging.ERROR)

br = mechanize.Browser()
br.set_handle_robots(False)  # Ignore robots
br.set_handle_refresh(False)  # Ignore refresh
br.addheaders = [('User-agent', 'Firefox')]

class Scanner():
    def __init__(self, first_url="", threads=0, cookie_file=None, show=False,
                 dbclear=False, ltest=False):
        self.ascii_art()
        if(show):
            self.show_data()
            sys.exit(0)
        if(dbclear):
            self.clear_db()
            sys.exit(0)
        self.parent_url = ""
        self.spidered_urls = []
        self.exploited_urls = []
        self.checked_urls = []
        self.vuln_urls = []
        self.first_url = first_url
        self.threads = int(threads)
        self.websites_to_scan = Queue.Queue()
        self.vectors = [
            '"><img src=. onerror="prompt(1)"/>', '"><script>alert(1)</script>'
            ]
        self.cookies = self.get_cookies(cookie_file)
        if (ltest):
            self.simple_test()
            sys.exit(0)
        self.domain = self.get_domain(first_url)
        self.first_request()

    def threading_manager(self):
        ''' Add items to the Queue '''
        for i in range(self.threads):  # Number of threads
            t1 = threading.Thread(target=self.scraper)
            t1.daemon = True
            t1.lock = threading.Lock()
            t1.start()  # Start the thread
            time.sleep(0.5)  # Avoid race conditions
        self.websites_to_scan.join()

    def get_domain(self, url):
        ''' Return the domain of scanned site and check if it's localhost '''
        if not ("localhost" in url):
            parent = urlparse(url)
            self.parent_url = parent.scheme + "://" + parent.netloc
            extracted = tldextract.extract(url)
            return "{}.{}".format(extracted.domain, extracted.suffix)
        self.parent_url = "http://localhost"
        return "localhost"

    def first_request(self):
        ''' 
            Start the first request and threads for every link, magic try/except here, 
            we dont want break the loop if one request fail
        '''
        print "[+] Scan in process:"
        res = br.open(self.first_url)
        if (res.code != 404):
            try:  # Handle misterius errors
                first_forms = self.get_forms(br)
                self.exploit(first_forms, self.first_url)
                self.spider(res.read(), self.first_url)
                self.threading_manager()
            except:
                pass

    def spider(self, html, url):
        '''
            Send spiders to all url checking his domain and the url ausence in <form action=""> tag (/path/to/file and ?arg= cases)
            Only spider href and action in order to avoid: .js .jpg .css .etc
        '''
        if not (url in self.spidered_urls):
            soup = BeautifulSoup(html, 'html.parser')
            # Scrap only important links avoiding src js/css/jpg
            tags_search = {"a": "href", "form": "action"}
            for key in tags_search.keys():
                for new_url in soup.find_all(key):
                    dst_url = new_url.get(tags_search[key])
                    if dst_url:
                        if dst_url != "#" and dst_url != "" and dst_url != ".":
                            if dst_url[:1] == "/":
                                dst_url = self.parent_url + dst_url
                            if dst_url[:1] == "?":
                                dst_url = url + dst_url
                            if self.domain in dst_url:
                                self.websites_to_scan.put(dst_url)
            self.spidered_urls.append(url)

    def scraper(self):
        ''' Recursive loop for the sitemap'''
        while not self.websites_to_scan.empty():
            try:  # Save the state after some mistery crash
                url = self.websites_to_scan.get()
                res = br.open(url)
                if (res.code != 404):
                    forms = self.get_forms(br)
                    self.exploit(forms, url)
                    self.spider(res.read(), url)
                    self.websites_to_scan.task_done()
                    self.scraper()
            except:
                self.websites_to_scan.task_done()

    def get_forms(self, br):
        ''' Get forms of the visited uri '''
        forms = []
        for form in br.forms():
            args = []
            for element in form.controls:
                if (element.name is not None and str.lower(element.name) != "submit"):
                    args.append({"name": element.name, "type": element.type})
            form = {"action": form.action, "method": form.method, "args": args}
            forms.append(form)
            return forms

    def exploit(self, forms, url):
        ''' Check for all vectors in all forms '''
        if not (url in self.exploited_urls):
            if (forms is not None):
                for form in forms:
                    for vector in self.vectors:
                        self.is_vulnerable(form['action'], form[
                                          'method'], form['args'], vector)
            self.exploited_urls.append(url)

    def is_vulnerable(self, url, method, args, vector):
        ''' Launch the vulnerability check '''
        payload = self.get_payload(method, args, vector)
        if not ("logout" in url):  # Save the client cookie/session to avoid server side session kill
            self.check(method, url, payload, vector)
        else:
            if(len(self.checked_urls) == (len(self.vuln_urls) - 1)):
                # check if the logout url is vulnerable at the end of all to avoid server side session kill
                self.check(method, url, payload, vector)
        self.checked_urls.append(url)

    def check(self, method, url, payload, vector):
        ''' Check the vulnerability in POST and GET Requests '''
        special_payloads = []
        if (method == "GET"):
            if not (url in self.vuln_urls):
                uri = url + "?" + payload
                r = requests.get(uri, verify=False,
                                 cookies=self.cookies, allow_redirects=True)
                if (vector in r.text):
                    for vuln in re.finditer(urllib.quote(vector), urllib.quote(r.text)):
                        start = vuln.start() - 1
                        special_payloads.append(urllib.unquote(urllib.quote(
                            r.text)[start:(start + len(urllib.quote(vector)) + 1)]))
                    print "[#] " + url + " Vulnerable!!"
                    args = parse_qs(urlparse(uri).query)
                    vulnerable_args = ""
                    for key in args.keys():
                        for special_payload in special_payloads:
                            if (special_payload in args[key][0]):
                                vulnerable_args += key + ","
                    self.save_in_database(method, url, vector,
                                          vulnerable_args, uri)
                    self.vuln_urls.append(url)
        if (method == "POST"):
            if not (url in self.vuln_urls):
                r = requests.post(url, data=payload, verify=False,
                                  cookies=self.cookies, allow_redirects=True)
                if (urllib.quote(vector) in r.text):
                    for vuln in re.finditer(urllib.quote(vector), r.text):
                        start = vuln.start() - 1
                        special_payloads.append(
                            r.text[start:(start + len(urllib.quote(vector)) + 1)])
                    print "[#] " + url + " Vulnerable!!"
                    args = parse_qs(
                        urlparse(url + "?" + self.get_post_string(payload)).query)
                    vulnerable_args = ""
                    for key in args.keys():
                        for special_payload in special_payloads:
                            if(special_payload[:-1] in urllib.quote(args[key][0])):
                                vulnerable_args += key + ","
                    self.save_in_database(method, url, vector, vulnerable_args,
                                          url + " Post Data: " + self.get_post_string(payload))
                    self.vuln_urls.append(url)

    def get_payload(self, method, args, vector):
        ''' Generate a special vulnerable payload for GET or POST '''
        num = 0
        payload = ""
        for arg in args:
            num += 1
            if method == "GET":
                payload += arg['name'] + "=" + str(num) + vector + "&"
            else:
                payload += arg['name'] + "=" + \
                    str(num) + urllib.quote(vector) + "&"

        if (method == "POST"):
            payload = self.payload2json(payload)
        else:
            payload = payload[:-1]
        return payload

    def payload2json(self, payload):
        ''' For requests data '''
        payload = payload[:-1]
        return dict((itm.split('=')[0], itm.split('=')[1]) for itm in payload.split('&'))

    def get_post_string(self, payload):
        ''' For check in html'''
        post_string = ""
        for key in payload.keys():
            post_string += key + "=" + payload[key] + "&"
        return post_string[:-1]

    def get_cookies(self, cookie_file):
        ''' Read cookie file and set it in requests and mechanize browser '''
        if(cookie_file):
            raw_cookies = open(cookie_file, "r").read().strip("Cookie: ").strip()
            if(len(raw_cookies) > 0):
                # Set cookie for first request
                br.addheaders.append(('Cookie', raw_cookies))
                return self.cookie2json(raw_cookies)
        return None

    def cookie2json(self, raw_cookies):
        ''' Raw cookies to json cookies for requests header '''
        return dict((itm.split('=')[0], itm.split('=')[1]) for itm in raw_cookies.split(';'))

    def save_in_database(self, method, url, vector, arguments, payloadUri):
        ''' Save in the database the method, the url, the vector and the vulnerable args'''
        if (method == "GET"):
            Vulnerabilities.create_or_get(method=method, url=url, vector=vector, get_arguments=arguments[
                                          :-1], payload_uri=payloadUri)
        if (method == "POST"):
            Vulnerabilities.create_or_get(method=method, url=url, vector=vector, post_arguments=arguments[
                                          :-1], payload_uri=payloadUri)

    def show_data(self, testFlag=False):
        ''' Show database registers '''
        result = []
        data = Vulnerabilities.select()
        headers = ["METHOD", "URL", "GET ARGUMENTS",
                   "POST ARGUMENTS", "VECTOR", "CREATED"]
        for row in data:
            result.append([row.method, row.url, row.get_arguments,
                           row.post_arguments, row.vector, row.created_date])
        if(testFlag is False):
            print ""
            print tabulate.tabulate(result, headers)
        else:
            if(len(result) == 0):
                print "[-] Testing Failed, Something is wrong"
            else:
                print "[+] All is good!"
                print ""
                print tabulate.tabulate(result, headers)

    def clear_db(self, testFlag=False):
        ''' Delete from Vulnerabilities table '''
        Vulnerabilities.delete().execute()
        if not testFlag:
            print "[#] Database clean done"

    def simple_test(self):
        ''' Start vulnerable server to check if the logic of the script works '''
        print "[+] Test in process:"
        subprocess.Popen(["test_server.py"])
        time.sleep(3)
        self.first_url = "http://localhost:9669/"
        self.threads = int("1")
        self.domain = "localhost"
        self.first_request()
        self.show_data(True)
        self.clear_db(True)

    def ascii_art(self):
        print '''
         __   __ _____ _____    _____  _____          _   _ _   _ ______ _____  
         \ \ / // ____/ ____|  / ____|/ ____|   /\   | \ | | \ | |  ____|  __ \ 
          \ V /| (___| (___   | (___ | |       /  \  |  \| |  \| | |__  | |__) |
           > <  \___ \\\\___ \   \___ \| |      / /\ \ | . ` | . ` |  __| |  _  / 
          / . \ ____) |___) |  ____) | |____ / ____ \| |\  | |\  | |____| | \ \ 
         /_/ \_\_____/_____/  |_____/ \_____/_/    \_\_| \_|_| \_|______|_|  \_\\
                                                            
                                                                    by hdbreaker
        '''