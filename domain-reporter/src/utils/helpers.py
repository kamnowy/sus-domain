import os
import psycopg2
import logging

log = logging.getLogger('app_log')

messageSet = set()

def consume_messages(user, password, host='postgers', db='certstream_db'):
    try:
        conn = psycopg2.connect(
            host=host,
            database=db,
            user=user,
            password=password
        )

        cur = conn.cursor()
        query = "SELECT id, domain_name, score FROM sus_domains WHERE check_domain = True;"
        log.debug(f"Executing query: {query} on db: {db}")
        cur.execute(query)
    
        results = cur.fetchall()

        for row in results:
            messageSet.add(row)
            log.debug(f"Fetched {row}")

        cur.close()
        conn.close()
    except Exception as e:
        log.error(f"Err while fetcing values from host: {host} db: {db} err: {e}")


def update_domain_in_db(domain_id, user, password, host='postgers', db='certstream_db'):
    try:
        conn = psycopg2.connect(
            host=host,
            database=db,
            user=user,
            password=password
        )

        cur = conn.cursor()
        query = "UPDATE sus_domains SET check_domain = False WHERE id=%s;"
        log.debug(f"Executing query {query} on: {db}")
        cur.execute(query, (domain_id,))
        conn.commit()
        log.debug(f"Values for id: {domain_id} updated successfully!")
        cur.close()
        conn.close()
    except Exception as e:
        log.error(f"Err while updating values from host: {host} db: {db} err: {e}")


def mark_domain_as_sus_in_db(domain_name, user, password, host='postgers', db='certstream_db'):
    try:
        conn = psycopg2.connect(
            host=host,
            database=db,
            user=user,
            password=password
        )

        cur = conn.cursor()
        query = "UPDATE sus_domains SET suspicious = True WHERE domain_name=%s;"
        log.debug(f"Executing query {query} on: {db}")
        cur.execute(query, (domain_name,))
        conn.commit()
        log.debug(f"Values for id: {domain_name} updated successfully!")
        cur.close()
        conn.close()
    except Exception as e:
        log.error(f"Err while updating values from host: {host} db: {db} err: {e}")


def get_config_var(env_name, value_from_config):
    # if env value is empty return value from config
    env_value = os.environ.get(env_name)

    if env_value == None or env_value == "":
        return value_from_config
    log.debug(f"Loaded value: {env_value} for config {env_name}")
    return env_value


