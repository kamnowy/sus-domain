#!/usr/bin/env python3
import time
from utils.external_apis import sendSlackMessage, run_test_domain_in_threads, domains_from_sus_registrar, scammers
from utils.helpers import consume_messages, get_config_var, update_domain_in_db, messageSet
import yaml
import logging.config

# Prepare config, read from config.yaml and envs
# If there's no env return value from config.yaml
config_yaml = '/var/configs/app_config.yaml'
with open(config_yaml, 'r') as f:
    config = yaml.safe_load(f)
slack_webhook_url_yaml = config['slack']['webhook_url']
db_host_yaml = config['db']['host']
db_username_yaml = config['db']['username']
db_password_yaml = config['db']['password']
db_name_yaml = config['db']['name']
slack_webhook_url = get_config_var('SEC_CST_SLACK_URL', slack_webhook_url_yaml)
db_host = get_config_var('SEC_CST_DB_HOST', db_host_yaml)
db_username = get_config_var('SEC_CST_DB_USERNAME', db_username_yaml)
db_password = get_config_var('SEC_CST_DB_PASSWORD', db_password_yaml)
db_name = get_config_var('SEC_CST_DB_NAME', db_name_yaml)
#get IOC from config

ioc_registrar_names = config['ioc']['registrar_names']
ioc_keywords_in_url = config['ioc']['keywords_in_url']


with open('/var/configs/logging_config.yaml', 'r') as f:
    log_config = yaml.safe_load(f)
    
logging.config.dictConfig(log_config)
log = logging.getLogger('app_log')


if __name__ == '__main__':

    time.sleep(15)
    
    consume_messages(user=db_username, password=db_password, host=db_host, db=db_name)

    run_test_domain_in_threads(messageSet, ioc_registrar_names, ioc_keywords_in_url)

    for domain in messageSet:
        log.debug(f"Updating domain: {domain[0]}")
        update_domain_in_db(user=db_username, password=db_password, host=db_host, db=db_name, domain_id=domain[0])

    sorted_set = sorted(messageSet, key=lambda x: x[2], reverse=True)

    if len(sorted_set)!= 0:
        new_domains = len(sorted_set)
        msg = f'Found {new_domains} new domains: '
        for el in sorted_set:
            msg = msg + f"{el[1]} {el[2]}, "
        if len(domains_from_sus_registrar) != 0:
            msg = msg + f"\nDomains registered by suspicoius registrar: {domains_from_sus_registrar}"
        if len(scammers)!= 0:
            scammers = set(scammers)
            msg = msg + f"\n:alert: found scammers site :alert: \n{scammers}"
        log.info(f"sending message via slack: {msg}")
        sendSlackMessage(msg)
