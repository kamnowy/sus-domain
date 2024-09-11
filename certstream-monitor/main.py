#!/usr/bin/env python
# Copyright (c) 2017 @x0rz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# oryginal repository: https://github.com/x0rz/phishing_catcher
# 
# Changes made by KN
#
from utils.helpers import score_domain, get_config_var, publish_data_to_db
import os
import time
import certstream
import yaml
import logging.config

# Prepare config, read from config.yaml and envs
# If there's no env return value from config.yaml
config_yaml = '/var/configs/app_config.yaml'

with open(config_yaml, 'r') as f:
    config = yaml.safe_load(f)
certstream_url_yaml = config['certstream']['url']
score_to_log_in_file_yaml = config['score']['to_log_in_file']
score_to_write_to_stdout_yaml = config['score']['to_write_to_stdout']
score_to_send_to_reporter_yaml = config['score']['to_send_to_reporter']
db_host_yaml = config['db']['host']
db_username_yaml = config['db']['username']
db_password_yaml = config['db']['password']
db_name_yaml = config['db']['name']

certstream_url = get_config_var('SEC_CST_CERTSTREAM_URL', certstream_url_yaml)
score_to_log_in_file = get_config_var('SEC_CST_SCORE_LOG', score_to_log_in_file_yaml)
score_to_write_to_stdout = get_config_var('SEC_CST_SCORE_STDOUT', score_to_write_to_stdout_yaml)
score_to_send_to_reporter = get_config_var('SEC_CST_SCORE_REPORT', score_to_send_to_reporter_yaml)
db_host = get_config_var('SEC_CST_DB_HOST', db_host_yaml)
db_username = get_config_var('SEC_CST_DB_USERNAME', db_username_yaml)
db_password = get_config_var('SEC_CST_DB_PASSWORD', db_password_yaml)
db_name = get_config_var('SEC_CST_DB_NAME', db_name_yaml)


with open('/var/configs/logging_config.yaml', 'r') as f:
    log_config = yaml.safe_load(f)
    
logging.config.dictConfig(log_config)
log = logging.getLogger('app_log')

suspicious_yaml = '/var/configs/suspicious.yaml'
with open(suspicious_yaml, 'r') as f:
    suspicious = yaml.safe_load(f)
    log.debug(suspicious)

log_suspicious = os.path.dirname(os.path.realpath(__file__))+'/suspicious_domains_'+time.strftime("%Y-%m-%d")+'.log'

def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        print(all_domains)

        for domain in all_domains:
            score = score_domain(domain.lower())

            # If issued from a free CA = more suspicious
            issuer = message['data']['leaf_cert']['issuer']['O']
            if issuer in suspicious['sus_issuers']:
                score += 20

            if score >= score_to_write_to_stdout:
                log.info(f"suspicious domain {domain} score={score}")

            if score >= score_to_send_to_reporter:
                publish_data_to_db(host=db_host, db=db_name, user=db_username, password=db_password, domain_name=domain, score=score, issuer=issuer)

            if score >= score_to_log_in_file:
                with open(log_suspicious, 'a') as f:
                    f.write("{}\n".format(domain))

if __name__ == '__main__':
    
    time.sleep(5)
    certstream.listen_for_events(callback, url=certstream_url)
