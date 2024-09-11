import whois
import requests
import json
import slack_sdk
import utils.helpers as helpers
import logging
import base64
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed



domains_from_sus_registrar = []
scammers = []
log = logging.getLogger('app_log')

def get_RDAP_registrar(domain, RDAP_URL):
    try:
        response = requests.get(f"{RDAP_URL}{domain}")
        if response.status_code == 200:
            data = response.json()
            registrar = data["entities"][0]["vcardArray"][1][1][3]
            log.debug(f"Registrar Name: {registrar} from the RDAP service: {RDAP_URL}{domain}")
            return registrar
        else:
            log.warning(f"Failed to retrieve Registrar Name data from the RDAP service: {RDAP_URL}{domain}")
            return -1
    except:
        return -1

def get_whois_registrar(domain):
    try:
        whoisData = whois.whois(domain)
        return whoisData.registrar
    except Exception as e:
        log.warning(f"Failed to retrieve Registrar Name data from WHOIS for domain: {domain}, error occured: {e}")
        return -1
    
    
def get_registar(domain):
    # Tries to get RDAP or Whois registrar data
    registrar = -1
    if registrar == -1:
        registrar = get_RDAP_registrar(domain, "https://rdap.iana.org/domain/")
    if registrar == -1:
        registrar = get_RDAP_registrar(domain, "https://rdap.verisign.com/com/v1/domain/")
    if registrar == -1:
        registrar=get_RDAP_registrar(domain, "https://rdap.gname.com/domain/")
    if registrar == -1:
        registrar= get_whois_registrar(domain)
    if registrar == -1:
        log.error(f"Cant find registar for: {domain}")
        registrar == 'registrar unknown'
    return registrar
    

def test_domain(domain, sus_registrars, keywords_in_urls):
    registrar = get_registar(domain)
    if registrar in sus_registrars:
        domains_from_sus_registrar.append(domain)
        for url, keywords in keywords_in_urls.items():
            test_for_keywords(url, domain, keywords)


def test_for_keywords(template, domain, keywords_dict):
    try:
        full_url = template.replace("sus-domain", domain)
        response = requests.get(full_url)     

        for keyword in keywords_dict:
            keyword = base64.b64decode(keyword).decode("utf-8")
            # if someone do "echo 'keywords' | base64" instead "echo -n 'keywords'| base64" echo will add tailng /n, remove tailing /n from string
            if keyword.endswith("\n"):
                keyword = keyword[:-1]
            if keyword in response.text:
                log.info(f"HTML CONTENT MATCH!!! {domain}, found {keyword} in {full_url}")
                scammers.append(domain)
                from helpers import mark_domain_as_sus_in_db
                from main import db_host, db_name, db_password, db_username
                log.debug(f"trying to set domain: {domain} as suspicious")
                mark_domain_as_sus_in_db(db_host=db_host, db_name=db_name, db_password=db_password, db_username=db_username, domain_name=domain)
    except requests.exceptions.ConnectionError as e:
        log.error(f"Connection error: {e}")
    except requests.exceptions.RequestException as e:
        log.error(f"Other request exception: {e}")  


def sendSlackMessage(msg):
    from main import slack_webhook_url
    webhook = slack_webhook_url
    payload = {"text": msg}
    return requests.post(webhook, json.dumps(payload))


def run_test_domain_in_threads(messageSet, ioc_registrar_names, ioc_keywords_in_url):
    max_threads = 10  # Maximum number of concurrent threads

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        
        for message in messageSet:
            domain = message[1]
            if domain.startswith("*."):
                domain = domain[2:]
            log.debug(f"Testing domain: {domain}")

            # Submit the test_domain function to the executor
            future = executor.submit(test_domain, domain, ioc_registrar_names, ioc_keywords_in_url)
            futures.append(future)

        # Wait for all futures to complete and handle results
        for future in as_completed(futures):
            try:
                future.result()  # This will raise an exception if the function raised one
            except Exception as e:
                log.error(f"Thread raised an exception: {e}")