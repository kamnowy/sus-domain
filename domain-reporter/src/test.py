from utils.external_apis import test_domain, scammers
import logging.config
import yaml

# Load logging configuration from YAML file
with open('/var/configs/logging_config.yaml', 'r') as f:
    log_config = yaml.safe_load(f)
    
logging.config.dictConfig(log_config)
log = logging.getLogger('app_log')

config_yaml = '/var/configs/app_config.yaml'
with open(config_yaml, 'r') as f:
    config = yaml.safe_load(f)
slack_webhook_url_yaml = config['slack']['webhook_url']
db_host_yaml = config['db']['host']
db_username_yaml = config['db']['username']
db_password_yaml = config['db']['password']
db_name_yaml = config['db']['name']
ioc_cert_issuer_organization_names = config['ioc']['cert_issuer_organization_name']
ioc_registrar_names = config['ioc']['registrar_names']
ioc_keywords_in_url = config['ioc']['keywords_in_url']
ioc_registrar_names = [x.lower() for x in ioc_registrar_names]

test_domain('example.domain',ioc_registrar_names,ioc_keywords_in_url)
