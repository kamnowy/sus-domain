from utils.helpers import score_domain, get_config_var, publish_data_to_db
import os
import yaml

def test_scoring_for_known_malicous_domains():
    """
    Test for scoring known malicous domains from yaml file test_score.yaml
    """
    # Prepare config, read from config.yaml and envs
    # If there's no env return value from config.yaml
    config_yaml = os.path.dirname(os.path.abspath(__file__))+'/config.yaml'
    with open(config_yaml, 'r') as f:
        config = yaml.safe_load(f)
    score_to_send_to_reporter_yaml = config['score']['to_send_to_reporter']
    score_to_send_to_reporter = get_config_var('SEC_CST_SCORE_REPORT', score_to_send_to_reporter_yaml)

    test_score = score_to_send_to_reporter
    test_score_yaml = os.path.dirname(os.path.realpath(__file__))+'/tests/test_score.yaml'

    with open(test_score_yaml, 'r') as f:
        domains = yaml.safe_load(f)
        print(domains)

    not_in_score = []

    for domain in domains['domains']:
        score = score_domain(domain=domain)
        print(f'{domain} {score}')
        if score < test_score:
            domain_with_score = {}
            domain_with_score[domain] = score
            not_in_score.append(domain_with_score)

    print(f'domains with score lower than {test_score}:{not_in_score}')

def test_connect_to_db():
    config_yaml = os.path.dirname(os.path.abspath(__file__))+'/config.yaml'
    config_yaml = '/var/configs/config.yaml'
    with open(config_yaml, 'r') as f:
        config = yaml.safe_load(f)
    db_host = config['db']['host']
    db_username = config['db']['username']
    db_password = config['db']['password']
    db_name = config['db']['name']

    publish_data_to_db(host=db_host, db=db_name, user=db_username, password=db_password, domain_name='test', issuer='test', score=12)


test_scoring_for_known_malicous_domains()

test_connect_to_db()