import re
import math
import yaml
import os
from Levenshtein import distance
from utils.confusables import unconfuse
import psycopg2
import logging

log = logging.getLogger('app_log')

suspicious_yaml = '/var/configs/suspicious.yaml'
with open(suspicious_yaml, 'r') as f:
    suspicious = yaml.safe_load(f)
    log.debug(suspicious)


def entropy(string):
    """Calculates the Shannon entropy of a string"""
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy


def score_domain(domain):
    """Score `domain`.

    The highest score, the most probable `domain` is a phishing site.

    Args:
        domain (str): the domain to check.

    Returns:
        int: the score of `domain`.
    """
    score = 0
    for t in suspicious['tlds']:
        if domain.endswith(t):
            score += 50
    
    # Remove initial '*.' for wildcard certificates bug and add score for wildcard
    if domain.count('.') >= 2:
        if domain.startswith("*.") and domain.count('.') == 2:
            score += 50
            domain = domain[2:]
        if domain.startswith("*."):
            domain = domain[2:]
            score = score - (domain.count('.') * 80)
        else:
            score = score - (domain.count('.') * 80)
        

    # Higer entropy is kind of suspicious
    # score += int(round(entropy(domain)*2))

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)

    words_in_domain = re.split("\W+", domain)

    # ie. detect fake .com (ie. *.com-account-management.info)
    if words_in_domain[0] in ['com', 'net', 'org']:
        score += 2

    # Testing keywords
    for word in suspicious['keywords']:
        if word in domain:
            score += suspicious['keywords'][word]
            if suspicious['keywords'][word] >0:
                log.debug(f"found {word}, adding score {suspicious['keywords'][word]} to {domain}")

    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    for key in [k for (k,s) in suspicious['keywords'].items() if s >= 70]:
        # Removing too generic keywords (ie. mail.domain.com)
        for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud', 'azure', 'mongo', 'dev']]:
            if distance(str(word), str(key)) == 1:
                score += 55

    log.debug(f"score for domain {domain} is: {score}")
    return score


def get_config_var(env_name, value_from_config):
    # if env value is empty return value from config
    env_value = os.environ.get(env_name)

    if env_value == None or env_value == "":
        return value_from_config
    
    log.debug(f"Loaded value: {env_value} for config {env_name}")
    return env_value


def publish_data_to_db(user, password, domain_name, score, issuer, host='postgers', db='certstream_db'):

    try:
        conn = psycopg2.connect(
            host=host,
            database=db,
            user=user,
            password=password
        )

        cur = conn.cursor()

        domain_name = domain_name
        score = score
        check_domain = True


        insert_sql = "INSERT INTO sus_domains (domain_name, score, check_domain, issuer) SELECT %s, %s, %s, %s WHERE NOT EXISTS (SELECT domain_name FROM sus_domains WHERE domain_name=%s);"
        log.debug(insert_sql)
        cur.execute(insert_sql, (domain_name, score, check_domain, issuer, domain_name,))
        conn.commit()

        insert_sql2 = "UPDATE sus_domains SET last_seen = now() WHERE domain_name=%s;"
        log.debug(insert_sql2)
        cur.execute(insert_sql2, (domain_name,))
        conn.commit()
        cur.close()
        conn.close()
        log.debug(f"Values for {domain_name} inserted to db!")
    except Exception as e:
        log.error(f"Err while inserting values to db for domain: {domain_name} err: {e}")
